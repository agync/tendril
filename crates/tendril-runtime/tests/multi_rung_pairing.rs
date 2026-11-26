//! Multi-rung pairing drivers: the Wire v1 race with one deferred commit and the sequential
//! Wire v2 rungs (`drive_pair_initiator_with_policy`, `drive_v2_pair_initiator_with_policy`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PairingUri, PersistOpts,
    RouteCheck, RoutePolicy, sign_route_statement,
};
use tendril_core::policy::ProviderId;
use tendril_core::roster::{RouteOrigin, RouteSource};
use tendril_core::v2::V2PairOutcome;
use tendril_relay::RelayConfig;
use tendril_runtime::providers::hints::{HintDialerConfig, HintDialers};
use tendril_runtime::{
    AttemptError, DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, EmbeddedRelay,
    PairPolicyOptions, PathDialer, PathListener, PathReader, PathStream, PathWriter,
    PrefixedPathStream, RelayListener, RosterAccess, RuntimeError, V2ResponderState,
    drive_pair_initiator_with_policy, drive_pair_responder, drive_v2_pair_initiator_with_policy,
    drive_v2_pake_pair_initiator_with_timeout, drive_v2_pake_pair_responder,
    initiator_argon2_available, initiator_argon2_peak, pairing_path_kind_for_provider, peek_exact,
    split_path_stream_fallback,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wire {
    V1,
    V2,
}

/// A pairing host serving its responder on any number of loopback listeners.
#[derive(Clone)]
struct Host {
    identity: Arc<EndpointIdentity>,
    manager: Arc<Mutex<PairingManager>>,
    roster: Arc<Mutex<tendril_core::roster::Roster>>,
    /// Connections that sent a Tendril preamble (foreign loopback probes are not counted).
    preambles: Arc<AtomicUsize>,
    wire: Wire,
    /// Delay before the responder reads `msg1`.
    delay: Duration,
}

impl Host {
    fn new(tag: u8, wire: Wire) -> Self {
        Self {
            identity: Arc::new(identity(tag)),
            manager: Arc::new(Mutex::new(PairingManager::new(PairingConfig::default()))),
            roster: Arc::new(Mutex::new(tendril_core::roster::Roster::new())),
            preambles: Arc::new(AtomicUsize::new(0)),
            wire,
            delay: Duration::ZERO,
        }
    }

    fn issue(&self) -> String {
        self.manager
            .lock()
            .unwrap()
            .issue_code(PairingCodeKind::Remote3Group, now())
            .expect("code")
    }

    fn live_codes(&self) -> usize {
        self.manager.lock().unwrap().live_code_count(now())
    }

    /// Devices the host recorded, i.e. claims (`msg3`) it accepted.
    fn claims(&self) -> usize {
        self.roster.lock().unwrap().entries().count()
    }

    async fn serve(&self) -> u16 {
        let listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .expect("bind");
        let port = listener.local_addr().port();
        self.serve_on(Box::new(listener));
        port
    }

    fn serve_on(&self, mut listener: Box<dyn PathListener>) {
        let host = self.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = listener.accept().await {
                let host = host.clone();
                tokio::spawn(async move {
                    let Ok(prefix) = peek_exact(stream.as_mut(), 3).await else {
                        return;
                    };
                    if !prefix.starts_with(b"TND") {
                        return;
                    }
                    host.preambles.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(host.delay).await;
                    let mut stream: Box<dyn PathStream> =
                        Box::new(PrefixedPathStream::new(stream, prefix));
                    let kind = pairing_path_kind_for_provider(stream.provider_id());
                    match host.wire {
                        Wire::V1 => {
                            let _ = drive_pair_responder(
                                stream.as_mut(),
                                &host.identity,
                                &host.manager,
                                &host.roster,
                                kind,
                                now(),
                                None,
                            )
                            .await;
                        }
                        Wire::V2 => {
                            let _ = drive_v2_pake_pair_responder(
                                stream.as_mut(),
                                &host.identity,
                                &host.manager,
                                &host.roster,
                                kind,
                                now(),
                                &V2ResponderState::new(),
                                None,
                            )
                            .await;
                        }
                    }
                });
            }
        });
    }
}

/// A loopback port with nothing listening.
async fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn base_uri(host: &Host, code: &str, hints: &[String]) -> PairingUri {
    PairingUri::new(
        "Studio",
        code,
        *host.identity.static_key().public_bytes(),
        host.identity.signing_key().signing_pub_hash(),
        hints.to_vec(),
        Some(host.identity.host_id().to_owned()),
        Some(0),
    )
}

/// The exact signed URI string for `hints` with route sequence `rq`.
fn signed_uri_string(host: &Host, code: &str, hints: &[String], rq: u64) -> String {
    let prefix = format!(
        "{}&rq={rq}",
        base_uri(host, code, hints).try_encode().expect("encode")
    );
    let sig = sign_route_statement(&host.identity, &prefix);
    format!("{prefix}&rs={}", b64url_encode(&sig))
}

fn signed_uri(host: &Host, code: &str, hints: &[String], rq: u64) -> PairingUri {
    PairingUri::parse(&signed_uri_string(host, code, hints, rq)).expect("parse")
}

fn unsigned_uri(host: &Host, code: &str, hints: &[String]) -> PairingUri {
    PairingUri::parse(&base_uri(host, code, hints).try_encode().expect("encode")).expect("parse")
}

fn direct(port: u16) -> String {
    format!("direct:127.0.0.1:{port}")
}

fn dialers() -> Arc<HintDialers> {
    Arc::new(HintDialers::new(HintDialerConfig::default()))
}

fn options(code: &str, uri: Option<PairingUri>) -> PairPolicyOptions {
    let mut opts = PairPolicyOptions::new("Phone", "phone", code, dialers());
    opts.uri = uri;
    opts
}

fn client() -> (Arc<EndpointIdentity>, RosterAccess) {
    (
        Arc::new(identity(0x42)),
        RosterAccess::memory(tendril_core::roster::Roster::new()),
    )
}

async fn pair(
    wire: Wire,
    store: &RosterAccess,
    opts: PairPolicyOptions,
) -> Result<(Vec<tendril_core::roster::StoredRoute>, RouteCheck, String), AttemptError> {
    let me = Arc::new(identity(0x42));
    match wire {
        Wire::V1 => {
            let res = drive_pair_initiator_with_policy(me, store, opts).await?;
            assert!(res.committed);
            assert!(matches!(
                res.drive.outcome,
                PairOutcome::InitiatorPending { .. }
            ));
            Ok((res.routes_persisted, res.route_check, res.route.addr))
        }
        Wire::V2 => {
            let res = drive_v2_pair_initiator_with_policy(me, store, opts).await?;
            assert!(res.committed);
            assert!(matches!(
                res.drive.outcome,
                V2PairOutcome::InitiatorPending { .. }
            ));
            Ok((res.routes_persisted, res.route_check, res.route.addr))
        }
    }
}

fn signed_routes(store: &RosterAccess, host: &Host) -> Vec<String> {
    let roster = store.load().unwrap();
    roster
        .get(host.identity.host_id())
        .map(|e| {
            e.routes_from(RouteSource::Signed)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

async fn signed_uri_persists_every_hint(wire: Wire) {
    let host = Host::new(0x11, wire);
    let code = host.issue();
    let live = direct(host.serve().await);
    let dead = direct(dead_port().await);
    let hints = vec![dead.clone(), live.clone()];
    let uri = signed_uri(&host, &code, &hints, 4);
    let (_, store) = client();

    let (persisted, check, winner) = pair(wire, &store, options(&code, Some(uri)))
        .await
        .expect("pair");

    assert_eq!(winner, live);
    assert!(matches!(check, RouteCheck::Verified(_)));
    assert_eq!(persisted.len(), 2, "every signed hint is persisted");
    assert_eq!(signed_routes(&store, &host), hints);
    let roster = store.load().unwrap();
    let meta = roster
        .get(host.identity.host_id())
        .and_then(|e| e.route_meta)
        .expect("route meta");
    assert_eq!((meta.seq, meta.origin), (4, RouteOrigin::Uri));
    assert_eq!(host.claims(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_signed_uri_persists_every_hint_past_a_dead_rung() {
    signed_uri_persists_every_hint(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_signed_uri_persists_every_hint_past_a_dead_rung() {
    signed_uri_persists_every_hint(Wire::V2).await;
}

async fn decoy_rung_fails_and_honest_rung_wins(wire: Wire) {
    let host = Host::new(0x12, wire);
    let decoy = Host::new(0x13, wire);
    let code = host.issue();
    decoy
        .manager
        .lock()
        .unwrap()
        .issue_code(PairingCodeKind::Remote3Group, now())
        .unwrap();
    let decoy_hint = direct(decoy.serve().await);
    let live = direct(host.serve().await);
    let uri = signed_uri(&host, &code, &[decoy_hint.clone(), live.clone()], 1);
    let (_, store) = client();

    let (_, _, winner) = pair(wire, &store, options(&code, Some(uri)))
        .await
        .expect("pair");
    assert_eq!(winner, live);
    assert_eq!(decoy.claims(), 0, "the decoy never receives msg3");
    assert_eq!(host.claims(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_decoy_host_rung_fails_and_honest_rung_wins() {
    decoy_rung_fails_and_honest_rung_wins(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_decoy_host_rung_fails_and_honest_rung_wins() {
    decoy_rung_fails_and_honest_rung_wins(Wire::V2).await;
}

async fn tampered_signed_uri_aborts_before_commit(wire: Wire) {
    let host = Host::new(0x14, wire);
    let code = host.issue();
    let signed_port = dead_port().await;
    let swapped = host.serve().await;
    let genuine = signed_uri_string(&host, &code, &[direct(signed_port)], 2);
    // The swapped route reaches the genuine host, so the pin passes; only `rs` catches it.
    let tampered = genuine.replace(&signed_port.to_string(), &swapped.to_string());
    assert_ne!(tampered, genuine);
    let uri = PairingUri::parse(&tampered).expect("parse");
    let (_, store) = client();

    let err = pair(wire, &store, options(&code, Some(uri)))
        .await
        .expect_err("tampered URI");
    assert!(
        matches!(&err.error, RuntimeError::Core(CoreError::InvalidPairingUri(m)) if m == "route statement does not verify"),
        "{err}"
    );
    assert!(!err.committed);
    assert_eq!(host.claims(), 0, "responder saw no msg3");
    assert_eq!(host.live_codes(), 1, "code still live");
    assert_eq!(
        store.load().unwrap().entries().count(),
        0,
        "nothing persisted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_tampered_signed_uri_aborts_before_commit() {
    tampered_signed_uri_aborts_before_commit(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_tampered_signed_uri_aborts_before_commit() {
    tampered_signed_uri_aborts_before_commit(Wire::V2).await;
}

async fn unsigned_uri_persists_by_policy(wire: Wire) {
    let host = Host::new(0x15, wire);
    let live = direct(host.serve().await);

    let code = host.issue();
    let (_, store) = client();
    let (persisted, check, _) = pair(
        wire,
        &store,
        options(
            &code,
            Some(unsigned_uri(&host, &code, std::slice::from_ref(&live))),
        ),
    )
    .await
    .expect("pair");
    assert_eq!(check.as_str(), "unsigned");
    assert!(persisted.is_empty(), "allSigned persists nothing unsigned");
    let roster = store.load().unwrap();
    let entry = roster.get(host.identity.host_id()).expect("pinned");
    assert!(entry.routes.is_empty() && entry.relay_hints.is_empty());

    let code = host.issue();
    let (_, store) = client();
    let mut opts = options(
        &code,
        Some(unsigned_uri(&host, &code, std::slice::from_ref(&live))),
    );
    opts.persist = PersistOpts {
        save_committed: true,
        ..PersistOpts::default()
    };
    let (persisted, _, _) = pair(wire, &store, opts).await.expect("pair");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].source, RouteSource::Committed);
    assert_eq!(persisted[0].hint, live);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_unsigned_uri_persists_only_the_committed_route_on_opt_in() {
    unsigned_uri_persists_by_policy(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_unsigned_uri_persists_only_the_committed_route_on_opt_in() {
    unsigned_uri_persists_by_policy(Wire::V2).await;
}

async fn code_override_uses_unsigned_rules(wire: Wire) {
    let host = Host::new(0x16, wire);
    let uri_code = host.issue();
    let typed_code = host.issue();
    let live = direct(host.serve().await);
    let uri = signed_uri(&host, &uri_code, &[live], 3);
    let (_, store) = client();

    let (persisted, check, _) = pair(wire, &store, options(&typed_code, Some(uri)))
        .await
        .expect("pair");
    assert_eq!(check.as_str(), "verified");
    assert!(
        persisted.is_empty(),
        "the statement is bound to another code"
    );
    assert_eq!(host.live_codes(), 1, "the URI code is untouched");
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_signed_uri_with_a_code_override_persists_nothing() {
    code_override_uses_unsigned_rules(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_signed_uri_with_a_code_override_persists_nothing() {
    code_override_uses_unsigned_rules(Wire::V2).await;
}

async fn committed_only_keeps_the_winner(wire: Wire) {
    let host = Host::new(0x17, wire);
    let code = host.issue();
    let live = direct(host.serve().await);
    let dead = direct(dead_port().await);
    let uri = signed_uri(&host, &code, &[dead, live.clone()], 2);
    let (_, store) = client();
    let mut opts = options(&code, Some(uri));
    opts.persist.policy = RoutePolicy::CommittedOnly;

    let (persisted, _, _) = pair(wire, &store, opts).await.expect("pair");
    assert_eq!(signed_routes(&store, &host), vec![live]);
    assert_eq!(persisted.len(), 1);

    let code = host.issue();
    let (_, store) = client();
    let live = direct(host.serve().await);
    let mut opts = options(&code, Some(signed_uri(&host, &code, &[live], 2)));
    opts.persist.policy = RoutePolicy::None;
    let (persisted, _, _) = pair(wire, &store, opts).await.expect("pair");
    assert!(persisted.is_empty());
    assert!(signed_routes(&store, &host).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_route_policies_committed_only_and_none() {
    committed_only_keeps_the_winner(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_route_policies_committed_only_and_none() {
    committed_only_keeps_the_winner(Wire::V2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_two_verified_rungs_commit_exactly_once() {
    // Two instances of one host, each holding the same live code: a claim on both would be
    // accepted twice.
    let host = Host {
        delay: Duration::from_millis(300),
        ..Host::new(0x18, Wire::V1)
    };
    let twin = Host {
        manager: Arc::new(Mutex::new(PairingManager::new(PairingConfig::default()))),
        roster: Arc::new(Mutex::new(tendril_core::roster::Roster::new())),
        preambles: Arc::new(AtomicUsize::new(0)),
        ..host.clone()
    };
    let entropy = [7u8; 64];
    let code = host
        .manager
        .lock()
        .unwrap()
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, now(), &entropy)
        .unwrap();
    let twin_code = twin
        .manager
        .lock()
        .unwrap()
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, now(), &entropy)
        .unwrap();
    assert_eq!(code, twin_code);
    let a = direct(host.serve().await);
    let b = direct(twin.serve().await);
    let mut opts = options(&code, Some(signed_uri(&host, &code, &[a, b], 1)));
    opts.policy_config.happy_eyeballs_stagger_ms = 0;
    let (_, store) = client();

    pair(Wire::V1, &store, opts).await.expect("pair");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        host.preambles.load(Ordering::SeqCst) + twin.preambles.load(Ordering::SeqCst),
        2,
        "both rungs were raced"
    );
    assert_eq!(
        host.claims() + twin.claims(),
        1,
        "one msg3 across both rungs"
    );
}

async fn guards_dial_nothing(wire: Wire) {
    let host = Host::new(0x19, wire);
    let port = host.serve().await;
    let overlay = format!("overlay://127.0.0.1:{port}");
    let (_, store) = client();

    // A two-group override code on a URI with remote-only hints.
    let lan_code = "TND-ABCD-EFGH";
    let uri = signed_uri(
        &host,
        "TND-ABCD-EFGH-JKLM",
        std::slice::from_ref(&overlay),
        1,
    );
    let err = pair(wire, &store, options(lan_code, Some(uri)))
        .await
        .expect_err("LAN code on a remote hint");
    assert!(
        matches!(
            err.error,
            RuntimeError::Core(CoreError::PairingPathDisallowed(_))
        ),
        "{err}"
    );
    assert_eq!(err.skipped.len(), 1);

    // A malformed effective code.
    let uri = signed_uri(&host, "TND-ABCD-EFGH-JKLM", &[direct(port)], 1);
    let err = pair(wire, &store, options("tnd-abcd-efgh", Some(uri)))
        .await
        .expect_err("malformed code");
    assert!(matches!(
        err.error,
        RuntimeError::Core(CoreError::PairingCodeInvalid)
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(host.preambles.load(Ordering::SeqCst), 0, "zero dials");
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_code_guards_dial_nothing() {
    guards_dial_nothing(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_code_guards_dial_nothing() {
    guards_dial_nothing(Wire::V2).await;
}

fn full_pin(host: &Host) -> tendril_core::pairing::PinnedHost {
    tendril_core::pairing::PinnedHost::with_full_key(
        Some(host.identity.host_id().to_owned()),
        *host.identity.static_key().public_bytes(),
        host.identity.signing_key().public_key().clone(),
        0,
    )
}

/// A caller pin of host A with a URI of host B is refused before any dial (`InvalidPairingUri`),
/// whichever host the URI hints reach; a pin that agrees with the URI pairs.
async fn caller_pin_must_match_the_uri_pin(wire: Wire) {
    let host_a = Host::new(0x1A, wire);
    let host_b = Host::new(0x1B, wire);
    let port_a = host_a.serve().await;
    let port_b = host_b.serve().await;
    let (_, store) = client();

    for port in [port_a, port_b] {
        let code = host_b.issue();
        let mut opts = options(&code, Some(signed_uri(&host_b, &code, &[direct(port)], 1)));
        opts.pinned_host = Some(full_pin(&host_a));
        let err = pair(wire, &store, opts)
            .await
            .expect_err("pin A with URI B");
        assert!(
            matches!(
                err.error,
                RuntimeError::Core(CoreError::InvalidPairingUri(_))
            ),
            "{err}"
        );
        assert!(!err.committed);
        assert!(err.failures.is_empty());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(host_a.preambles.load(Ordering::SeqCst), 0, "zero dials");
    assert_eq!(host_b.preambles.load(Ordering::SeqCst), 0, "zero dials");

    let code = host_b.issue();
    let mut opts = options(
        &code,
        Some(signed_uri(&host_b, &code, &[direct(port_b)], 1)),
    );
    opts.pinned_host = Some(full_pin(&host_b));
    pair(wire, &store, opts).await.expect("matching pin pairs");
    assert_eq!(host_b.claims(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_caller_pin_must_match_the_uri_pin() {
    caller_pin_must_match_the_uri_pin(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_caller_pin_must_match_the_uri_pin() {
    caller_pin_must_match_the_uri_pin(Wire::V2).await;
}

/// Forwards each connection to `upstream` and drops every host byte once the client has written
/// after the host's first reply (its `msg3`), so the `PairResponse` is lost and the client sees
/// the stream close.
async fn lossy_proxy(upstream: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(server) =
                    TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], upstream))).await
                else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let replied = Arc::new(AtomicBool::new(false));
                let claimed = Arc::new(AtomicBool::new(false));
                let (replied_c, claimed_c) = (Arc::clone(&replied), Arc::clone(&claimed));
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65_536];
                    while let Ok(n) = sr.read(&mut buf).await {
                        if n == 0 || claimed_c.load(Ordering::SeqCst) {
                            break;
                        }
                        replied_c.store(true, Ordering::SeqCst);
                        if cw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    drop(cw);
                });
                let mut buf = vec![0u8; 65_536];
                while let Ok(n) = cr.read(&mut buf).await {
                    if replied.load(Ordering::SeqCst) {
                        claimed.store(true, Ordering::SeqCst);
                    }
                    if n == 0 || sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn lost_pair_response_is_committed(wire: Wire) {
    let host = Host::new(0x1A, wire);
    let code = host.issue();
    let upstream = host.serve().await;
    let lossy = direct(lossy_proxy(upstream).await);
    let backup_host = Host::new(0x1A, wire);
    let backup = direct(backup_host.serve().await);
    let uri = signed_uri(&host, &code, &[lossy, backup], 1);
    let (_, store) = client();
    let mut opts = options(&code, Some(uri));
    opts.handshake_timeout = Duration::from_secs(3);
    // The backup rung is never raced before the first one verifies.
    opts.policy_config.happy_eyeballs_stagger_ms = 60_000;

    let err = pair(wire, &store, opts).await.expect_err("lost response");
    assert!(err.committed, "{err}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(host.claims(), 1, "the host accepted the one claim");
    assert_eq!(
        backup_host.preambles.load(Ordering::SeqCst),
        0,
        "no other rung after the commit"
    );
    assert_eq!(
        store.load().unwrap().entries().count(),
        0,
        "nothing persisted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_lost_pair_response_is_committed_and_final() {
    lost_pair_response_is_committed(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_lost_pair_response_is_committed_and_final() {
    lost_pair_response_is_committed(Wire::V2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_initiator_derivations_share_a_process_wide_bound() {
    let me = Arc::new(identity(0x43));
    let mut attempts = Vec::new();
    for _ in 0..4 {
        let me = Arc::clone(&me);
        attempts.push(tokio::spawn(async move {
            // A host that accepts and never answers: each attempt derives once, then times out.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let held = tokio::spawn(async move {
                let conn = listener.accept().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(conn);
            });
            let mut stream = tendril_runtime::DirectDialer::new()
                .connect(addr)
                .await
                .expect("connect");
            let res = drive_v2_pake_pair_initiator_with_timeout(
                stream.as_mut(),
                &me,
                "Phone".into(),
                "phone".into(),
                "TND-ABCD-EFGH-JKLM".into(),
                None,
                Duration::from_millis(200),
            )
            .await;
            held.abort();
            res.is_err()
        }));
    }
    for attempt in attempts {
        assert!(attempt.await.unwrap(), "no host answers");
    }
    let peak = initiator_argon2_peak();
    assert!(
        (1..=2).contains(&peak),
        "peak concurrent derivations {peak}"
    );
}

/// Fault injected on a candidate stream once the host's first reply (`msg2`) arrived: every
/// later write is a claim (`msg3`) write.
#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    /// The first claim write fails before any byte is written.
    FirstWriteError,
    /// The first claim write delivers half its bytes, then fails.
    PartialWrite,
    /// The read that delivers the first reply blocks its worker this long before returning,
    /// so the budget expires between verification and the claim.
    StallFirstRead(Duration),
}

/// What the spy dialer saw: each dial with the free initiator Argon2id permits at that moment,
/// and every write a stream made after the host's first reply.
#[derive(Clone, Default)]
struct Spy {
    dials: Arc<Mutex<Vec<(String, usize)>>>,
    claim_writes: Arc<AtomicUsize>,
}

/// The `Direct` base dialer of a [`HintDialers`] set, wrapping each stream in a [`FaultStream`].
struct FaultDialer {
    fault: Fault,
    spy: Spy,
}

#[async_trait::async_trait]
impl PathDialer for FaultDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.spy
            .dials
            .lock()
            .unwrap()
            .push((endpoint.to_owned(), initiator_argon2_available()));
        let inner = DirectDialer::new().dial(endpoint).await?;
        Ok(Box::new(FaultStream {
            inner,
            fault: self.fault,
            received: false,
            claim_writes: Arc::clone(&self.spy.claim_writes),
        }))
    }
}

struct FaultStream {
    inner: Box<dyn PathStream>,
    fault: Fault,
    received: bool,
    claim_writes: Arc<AtomicUsize>,
}

fn broken_pipe() -> RuntimeError {
    RuntimeError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "injected claim write fault",
    ))
}

#[async_trait::async_trait]
impl PathStream for FaultStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if self.received {
            self.claim_writes.fetch_add(1, Ordering::SeqCst);
            match self.fault {
                Fault::FirstWriteError => return Err(broken_pipe()),
                Fault::PartialWrite => {
                    self.inner.send_chunk(&bytes[..bytes.len() / 2]).await?;
                    return Err(broken_pipe());
                }
                Fault::None | Fault::StallFirstRead(_) => {}
            }
        }
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        let n = self.inner.recv_chunk(buf).await?;
        if n > 0 && !self.received {
            self.received = true;
            if let Fault::StallFirstRead(stall) = self.fault {
                std::thread::sleep(stall);
            }
        }
        Ok(n)
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        split_path_stream_fallback(self)
    }
}

fn spied_dialers(fault: Fault, spy: &Spy) -> Arc<HintDialers> {
    Arc::new(
        HintDialers::new(HintDialerConfig::default()).with_provider_dialer(Arc::new(FaultDialer {
            fault,
            spy: spy.clone(),
        })),
    )
}

async fn claim_write_fault_is_committed_and_final(wire: Wire, fault: Fault) {
    let host = Host::new(0x1B, wire);
    let code = host.issue();
    let first = direct(host.serve().await);
    let backup = direct(host.serve().await);
    let spy = Spy::default();
    let mut opts = options(&code, Some(signed_uri(&host, &code, &[first, backup], 1)));
    opts.dialers = spied_dialers(fault, &spy);
    // The backup rung is never raced before the first one verifies.
    opts.policy_config.happy_eyeballs_stagger_ms = 60_000;
    let (_, store) = client();

    let err = pair(wire, &store, opts)
        .await
        .expect_err("claim write fault");
    assert!(err.committed, "{fault:?}: {err}");
    assert!(matches!(err.error, RuntimeError::Io(_)), "{fault:?}: {err}");
    assert_eq!(
        spy.claim_writes.load(Ordering::SeqCst),
        1,
        "{fault:?}: one claim write, never rebuilt or retried"
    );
    assert_eq!(
        spy.dials.lock().unwrap().len(),
        1,
        "{fault:?}: no other rung after the commit"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        host.claims(),
        0,
        "{fault:?}: no complete msg3 reached the host"
    );
    assert_eq!(
        store.load().unwrap().entries().count(),
        0,
        "{fault:?}: nothing persisted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_claim_write_errors_are_committed_and_final() {
    claim_write_fault_is_committed_and_final(Wire::V1, Fault::FirstWriteError).await;
    claim_write_fault_is_committed_and_final(Wire::V1, Fault::PartialWrite).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_claim_write_errors_are_committed_and_final() {
    claim_write_fault_is_committed_and_final(Wire::V2, Fault::FirstWriteError).await;
    claim_write_fault_is_committed_and_final(Wire::V2, Fault::PartialWrite).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_budget_expiring_before_the_claim_write_stays_uncommitted() {
    let host = Host::new(0x1C, Wire::V1);
    let code = host.issue();
    let rung = direct(host.serve().await);
    let spy = Spy::default();
    let budget = Duration::from_millis(800);
    let mut opts = options(&code, Some(signed_uri(&host, &code, &[rung], 1)));
    opts.dialers = spied_dialers(
        Fault::StallFirstRead(budget + Duration::from_millis(400)),
        &spy,
    );
    opts.handshake_timeout = budget;
    let (_, store) = client();

    let err = pair(Wire::V1, &store, opts)
        .await
        .expect_err("budget expired before the claim");
    assert!(!err.committed, "{err}");
    assert!(matches!(err.error, RuntimeError::Timeout(_)), "{err}");
    assert_eq!(spy.claim_writes.load(Ordering::SeqCst), 0, "no msg3 byte");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(host.claims(), 0);
    assert_eq!(host.live_codes(), 1, "the code is still live");
}

/// Accepts TCP and closes each connection as soon as its Tendril preamble arrives.
async fn closing_host() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 3];
                let _ = conn.read_exact(&mut buf).await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_policy_rungs_wait_for_the_kdf_permit_before_dialing() {
    const PERMITS: usize = tendril_runtime::DEFAULT_INITIATOR_ARGON2_PERMITS;
    let keys = Host::new(0x1D, Wire::V2);
    let code = "TND-ABCD-EFGH-JKLM";
    let port = closing_host().await;
    let spy = Spy::default();
    let dialers = spied_dialers(Fault::None, &spy);
    let attempt = |hint: String| {
        let mut opts = options(code, Some(unsigned_uri(&keys, code, &[hint])));
        opts.dialers = Arc::clone(&dialers);
        async move {
            let (me, store) = client();
            drive_v2_pair_initiator_with_policy(me, &store, opts)
                .await
                .map(|_| ())
        }
    };

    // Far more rungs than permits: each one dials only once it holds a permit.
    let saturating: Vec<_> = (0..16)
        .map(|_| tokio::spawn(attempt(direct(port))))
        .collect();
    tokio::time::sleep(Duration::from_millis(15)).await;

    // A queued attempt cancelled before it gets a permit has dialed nothing.
    let queued_port = closing_host().await;
    let queued = tokio::spawn(attempt(direct(queued_port)));
    tokio::time::sleep(Duration::from_millis(5)).await;
    queued.abort();

    // The legacy single-stream driver bounds its permit wait by its own budget.
    let mut stream = DirectDialer::new()
        .connect(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    let err = drive_v2_pake_pair_initiator_with_timeout(
        stream.as_mut(),
        &identity(0x45),
        "Phone".into(),
        "phone".into(),
        code.into(),
        None,
        Duration::from_millis(10),
    )
    .await
    .expect_err("no permit within the budget");
    assert!(
        matches!(err, RuntimeError::Timeout(m) if m == "argon2id permit wait timed out"),
        "{err}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));

    for attempt in saturating {
        assert!(attempt.await.unwrap().is_err(), "no host answers");
    }
    let dials = spy.dials.lock().unwrap().clone();
    assert_eq!(dials.len(), 16, "{dials:?}");
    assert!(
        dials.iter().all(|(_, free)| *free < PERMITS),
        "every rung held its permit when it dialed: {dials:?}"
    );
    assert!(
        dials
            .iter()
            .all(|(ep, _)| !ep.ends_with(&format!(":{queued_port}"))),
        "the cancelled attempt never dialed"
    );
    assert_eq!(
        initiator_argon2_peak(),
        PERMITS,
        "derivations ran in parallel"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while initiator_argon2_available() != PERMITS {
        assert!(
            std::time::Instant::now() < deadline,
            "permits are released after cancellation"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wrong_rp_fails_before_commit(wire: Wire) {
    let host = Host::new(0x1E, wire);
    let code = host.issue();
    // The genuine host answers on the relay mailbox of another key.
    let decoy = SigningKeypair::from_seed([0x7E; 32]);
    let relay = EmbeddedRelay::start(RelayConfig {
        host: "127.0.0.1".to_owned(),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let listener = RelayListener::bind(
        relay.ws_url(),
        None,
        decoy.ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .unwrap();
    host.serve_on(Box::new(listener));
    let mut uri = base_uri(&host, &code, &[relay.ws_url()]);
    uri.relay_pub = Some(*decoy.public_key().ed25519_bytes());
    let prefix = format!("{}&rq=1", uri.try_encode().expect("encode"));
    let sig = sign_route_statement(&host.identity, &prefix);
    let uri = PairingUri::parse(&format!("{prefix}&rs={}", b64url_encode(&sig))).expect("parse");
    let (_, store) = client();

    let err = pair(wire, &store, options(&code, Some(uri)))
        .await
        .expect_err("wrong rp");
    assert!(!err.committed, "{err}");
    assert!(
        matches!(err.error, RuntimeError::Core(CoreError::HostKeyUnverified)),
        "{err}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        host.preambles.load(Ordering::SeqCst),
        1,
        "the host was reached"
    );
    assert_eq!(host.claims(), 0, "no msg3");
    assert_eq!(host.live_codes(), 1, "the code is still live");
    assert_eq!(store.load().unwrap().entries().count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_wrong_rp_fails_before_commit() {
    wrong_rp_fails_before_commit(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_wrong_rp_fails_before_commit() {
    wrong_rp_fails_before_commit(Wire::V2).await;
}
