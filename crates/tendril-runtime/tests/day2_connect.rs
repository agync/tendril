//! Day-2 connect over stored routes (`connect_with_policy_and_store`, Wire v1 and v2): candidate
//! building from routes only, the final authorization check, recovery URIs, route set ingest
//! and the Happy Eyeballs ladder timing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{PairingUri, RouteCheck, RoutePolicy, sign_route_statement};
use tendril_core::policy::ProviderId;
use tendril_core::roster::{
    OperatorEndpoint, PeerState, Roster, RouteOrigin, RouteSource, V2PeerSecrets,
};
use tendril_core::routes::RouteSet;
use tendril_core::v2::PaddingPolicy;
use tendril_relay::RelayConfig;
use tendril_runtime::providers::egress::SkipReason;
use tendril_runtime::providers::hints::{HintDialerConfig, HintDialers, peer_routes_in};
use tendril_runtime::{
    AddressSource, AdvertiseInputs, AdvertiseMode, AttemptError, ConcurrentSession,
    ConcurrentV2Session, ConnectOpts, ConnectResult, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, EmbeddedRelay, PathDialer, PathListener,
    PathReader, PathStream, PathWriter, PrefixedPathStream, RecoveryRoutes, RelayListener,
    RelayV2Listener, RosterAccess, RouteAnnouncer, RouteSetSink, RuntimeError, SessionDriver,
    SessionEvent, StateStore, V2ResponderConfig, V2ResponderState, V2SessionDriver, peek_exact,
    split_path_stream_fallback,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

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

fn secrets() -> V2PeerSecrets {
    V2PeerSecrets::new([0x31; 32], [0x32; 32])
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wire {
    V1,
    V2,
}

enum HostSession {
    V1(Arc<ConcurrentSession>),
    V2(Arc<ConcurrentV2Session>),
}

impl HostSession {
    fn sink(&self) -> Arc<dyn RouteSetSink> {
        match self {
            Self::V1(s) => Arc::clone(s) as Arc<dyn RouteSetSink>,
            Self::V2(s) => Arc::clone(s) as Arc<dyn RouteSetSink>,
        }
    }

    fn peer_route_seq(&self) -> Option<u64> {
        match self {
            Self::V1(s) => s.peer_route_seq(),
            Self::V2(s) => s.peer_route_seq(),
        }
    }

    async fn send_data(&self, data: &[u8]) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_data(data).await,
            Self::V2(s) => s.send_data(data).await,
        }
    }
}

/// A paired session host accepting on any number of listeners.
#[derive(Clone)]
struct Host {
    identity: Arc<EndpointIdentity>,
    roster: Arc<Mutex<Roster>>,
    wire: Wire,
    /// Connections that sent a Tendril preamble, and when the first one did.
    preambles: Arc<AtomicUsize>,
    first_preamble: Arc<Mutex<Option<Instant>>>,
    established: Arc<AtomicUsize>,
    delay: Duration,
    sessions: mpsc::UnboundedSender<HostSession>,
    v2_state: Arc<V2ResponderState>,
}

impl Host {
    fn new(
        tag: u8,
        wire: Wire,
        client: &EndpointIdentity,
    ) -> (Self, mpsc::UnboundedReceiver<HostSession>) {
        Self::with_identity(identity(tag), wire, client)
    }

    /// A host with `identity` (for example a rotated one) that has `client` paired.
    fn with_identity(
        identity: EndpointIdentity,
        wire: Wire,
        client: &EndpointIdentity,
    ) -> (Self, mpsc::UnboundedReceiver<HostSession>) {
        let mut roster = Roster::new();
        roster
            .record_pending_pair(
                *client.static_key().public_bytes(),
                None,
                "Phone".into(),
                "phone".into(),
                "1234".into(),
            )
            .unwrap();
        roster
            .confirm_peer(&client.device_id(), Some("1234"))
            .unwrap();
        if wire == Wire::V2 {
            roster
                .upgrade_peer_to_v2(&client.device_id(), secrets())
                .unwrap();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                identity: Arc::new(identity),
                roster: Arc::new(Mutex::new(roster)),
                wire,
                preambles: Arc::new(AtomicUsize::new(0)),
                first_preamble: Arc::new(Mutex::new(None)),
                established: Arc::new(AtomicUsize::new(0)),
                delay: Duration::ZERO,
                sessions: tx,
                v2_state: Arc::new(V2ResponderState::new()),
            },
            rx,
        )
    }

    fn id(&self) -> String {
        self.identity.host_id().to_owned()
    }

    fn serve_on(&self, mut listener: Box<dyn PathListener>) {
        let host = self.clone();
        tokio::spawn(async move {
            while let Ok(stream) = listener.accept().await {
                let host = host.clone();
                tokio::spawn(async move { host.handle(stream).await });
            }
        });
    }

    async fn serve(&self) -> u16 {
        let listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let port = listener.local_addr().port();
        self.serve_on(Box::new(listener));
        port
    }

    async fn handle(&self, mut stream: Box<dyn PathStream>) {
        let Ok(prefix) = peek_exact(stream.as_mut(), 3).await else {
            return;
        };
        if !prefix.starts_with(b"TND") {
            return;
        }
        self.preambles.fetch_add(1, Ordering::SeqCst);
        self.first_preamble
            .lock()
            .unwrap()
            .get_or_insert_with(Instant::now);
        tokio::time::sleep(self.delay).await;
        let stream: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(stream, prefix));
        let session = match self.wire {
            Wire::V1 => SessionDriver::accept_locked(
                stream,
                &self.identity,
                &self.roster,
                now(),
                None,
                None,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map(|s| HostSession::V1(Arc::new(s.into_concurrent()))),
            Wire::V2 => V2SessionDriver::accept_locked(
                stream,
                &self.identity,
                &self.roster,
                now(),
                &self.v2_state,
                None,
                None,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map(|s| HostSession::V2(Arc::new(s.into_concurrent()))),
        };
        if let Ok(session) = session {
            self.established.fetch_add(1, Ordering::SeqCst);
            let _ = self.sessions.send(session);
        }
    }

    /// A URI with this host's current keys; `rp` is its current mailbox key when a hint is a
    /// `/v1/relay` URL.
    fn base_uri(&self, hints: &[String]) -> PairingUri {
        let mut uri = PairingUri::new(
            "Studio",
            "TND-ABCD-EFGH-JKLM",
            *self.identity.static_key().public_bytes(),
            self.identity.signing_key().signing_pub_hash(),
            hints.to_vec(),
            Some(self.id()),
            Some(self.identity.rotation_seq()),
        );
        if hints.iter().any(|h| h.ends_with("/v1/relay")) {
            uri.relay_pub = Some(*self.identity.signing_key().public_key().ed25519_bytes());
        }
        uri
    }

    fn signed_uri_string(&self, hints: &[String], rq: u64) -> String {
        let prefix = format!(
            "{}&rq={rq}",
            self.base_uri(hints).try_encode().expect("encode")
        );
        let sig = sign_route_statement(&self.identity, &prefix);
        format!("{prefix}&rs={}", b64url_encode(&sig))
    }

    fn route_set(&self, seq: u64, routes: &[String]) -> Vec<u8> {
        RouteSet::sign(&self.identity, seq, now(), routes.to_vec())
            .expect("sign")
            .encode()
    }
}

fn direct(port: u16) -> String {
    format!("direct:127.0.0.1:{port}")
}

async fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// The client's roster: an `Active` pin of `host` (Wire v2 secrets when the host is v2).
fn client_roster(host: &Host) -> Roster {
    client_roster_for(&host.identity, host.wire)
}

/// The client's roster pinning `pin` (for example a host's keys before it rotated).
fn client_roster_for(pin: &EndpointIdentity, wire: Wire) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            pin.host_id().to_owned(),
            "Studio".into(),
            *pin.static_key().public_bytes(),
            Some(pin.signing_key().public_key().clone()),
            pin.rotation_seq(),
            Vec::new(),
        )
        .unwrap();
    if wire == Wire::V2 {
        roster.upgrade_peer_to_v2(pin.host_id(), secrets()).unwrap();
    }
    roster
}

/// `base` after one rotation to keys derived from `tag`.
fn rotated(base: &EndpointIdentity, tag: u8) -> EndpointIdentity {
    let mut id = base.clone();
    id.rotate(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
        now(),
    )
    .expect("rotate");
    id
}

fn set_operator(roster: &mut Roster, peer: &str, hints: &[String]) {
    let eps = hints
        .iter()
        .map(|h| OperatorEndpoint {
            hint: h.clone(),
            relay_key: None,
        })
        .collect();
    roster.set_routes(peer, eps).unwrap();
}

fn set_signed(roster: &mut Roster, host: &Host, hints: &[String], rq: u64) {
    let uri = PairingUri::parse(&host.signed_uri_string(hints, rq)).unwrap();
    let RouteCheck::Verified(s) =
        uri.verify_route_statement(host.identity.signing_key().public_key())
    else {
        panic!("statement");
    };
    assert!(roster.replace_signed_routes(&host.id(), &s).unwrap());
}

fn routes(store: &RosterAccess, peer: &str, source: RouteSource) -> Vec<String> {
    store
        .load()
        .unwrap()
        .get(peer)
        .unwrap()
        .routes_from(source)
        .map(str::to_owned)
        .collect()
}

fn opts() -> ConnectOpts {
    ConnectOpts::new(Arc::new(HintDialers::new(HintDialerConfig::default())))
}

enum Client {
    V1(SessionDriver),
    V2(V2SessionDriver),
}

impl Client {
    async fn next_event(&mut self, roster: &Mutex<Roster>) -> Option<SessionEvent> {
        let fut = async {
            match self {
                Self::V1(s) => s.next_event_locked_now(roster).await,
                Self::V2(s) => s.next_event_locked_now(roster).await,
            }
        };
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .expect("event in time")
            .expect("event")
    }
}

async fn connect(
    wire: Wire,
    me: &Arc<EndpointIdentity>,
    target: &str,
    store: &RosterAccess,
    opts: ConnectOpts,
) -> Result<ConnectResult<Client>, AttemptError> {
    match wire {
        Wire::V1 => {
            SessionDriver::connect_with_policy_and_store(Arc::clone(me), target, store, opts)
                .await
                .map(|r| ConnectResult {
                    route: r.route,
                    session: Client::V1(r.session),
                    skipped: r.skipped,
                    failures: r.failures,
                    recovery_routes: r.recovery_routes,
                })
        }
        Wire::V2 => {
            V2SessionDriver::connect_with_policy_and_store(Arc::clone(me), target, store, opts)
                .await
                .map(|r| ConnectResult {
                    route: r.route,
                    session: Client::V2(r.session),
                    skipped: r.skipped,
                    failures: r.failures,
                    recovery_routes: r.recovery_routes,
                })
        }
    }
}

async fn operator_routes_fall_back(wire: Wire) {
    let me = Arc::new(identity(0x50));
    let (host, mut rx) = Host::new(0x60, wire, &me);
    let dead = direct(dead_port().await);
    let live = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), &[dead.clone(), live.clone()]);
    let store = RosterAccess::memory(roster);

    let res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("connect");
    assert_eq!(res.route.addr, live);
    assert!(res.failures.iter().any(|f| f.hint == dead));
    rx.recv().await.expect("host session");
    assert_eq!(host.established.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_operator_routes_fall_back_past_a_dead_route() {
    operator_routes_fall_back(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_operator_routes_fall_back_past_a_dead_route() {
    operator_routes_fall_back(Wire::V2).await;
}

async fn legacy_relay_hints_are_never_dialed(wire: Wire) {
    let me = Arc::new(identity(0x51));
    let (host, _rx) = Host::new(0x61, wire, &me);
    let port = host.serve().await;
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.id(),
            "Studio".into(),
            *host.identity.static_key().public_bytes(),
            Some(host.identity.signing_key().public_key().clone()),
            0,
            vec![direct(port)],
        )
        .unwrap();
    if wire == Wire::V2 {
        roster.upgrade_peer_to_v2(&host.id(), secrets()).unwrap();
    }
    let store = RosterAccess::memory(roster);

    let err = connect(wire, &me, &host.id(), &store, opts())
        .await
        .err()
        .expect("no stored routes");
    let msg = err.to_string();
    assert!(msg.contains("no dialable stored routes"), "{msg}");
    assert!(msg.contains("legacy relay hints"), "{msg}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(host.preambles.load(Ordering::SeqCst), 0, "zero dials");
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_legacy_relay_hints_are_never_dialed() {
    legacy_relay_hints_are_never_dialed(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_legacy_relay_hints_are_never_dialed() {
    legacy_relay_hints_are_never_dialed(Wire::V2).await;
}

async fn announced_routes_replace_stale_ones(wire: Wire) {
    let me = Arc::new(identity(0x52));
    let (host, mut rx) = Host::new(0x62, wire, &me);
    let a = direct(host.serve().await);
    let b = direct(host.serve().await);
    let o = direct(dead_port().await);
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, std::slice::from_ref(&a), 1);
    set_operator(&mut roster, &host.id(), std::slice::from_ref(&o));
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(StateStore::open_or_create(dir.path()).unwrap());
    state.save_roster(&roster).unwrap();
    let store = RosterAccess::from_store(Arc::clone(&state)).unwrap();

    let mut res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("connect");
    let session = rx.recv().await.expect("host session");
    assert_eq!(session.peer_route_seq(), Some(0), "route_seq of a URI meta");
    session
        .sink()
        .send_route_set(&host.route_set(2, std::slice::from_ref(&b)))
        .await
        .expect("route set");
    session.send_data(b"after").await.expect("data");
    let client_roster = Mutex::new(store.load().unwrap());
    assert_eq!(
        res.session.next_event(&client_roster).await,
        Some(SessionEvent::AppData(b"after".to_vec())),
        "the route set never reaches the event stream"
    );

    assert_eq!(
        routes(&store, &host.id(), RouteSource::Signed),
        vec![b.clone()]
    );
    assert_eq!(routes(&store, &host.id(), RouteSource::Operator), vec![o]);
    let meta = store
        .load()
        .unwrap()
        .get(&host.id())
        .unwrap()
        .route_meta
        .unwrap();
    assert_eq!((meta.seq, meta.origin), (2, RouteOrigin::Session));
    assert_eq!(
        store.last_route_set(&host.id()).map(|l| l.outcome),
        Some("applied")
    );
    let view = peer_routes_in(&store, &host.id()).unwrap();
    assert_eq!(
        view.last_route_set.map(|l| (l.outcome, l.seq)),
        Some(("applied", 2))
    );
    assert_eq!(view.route_meta.map(|m| m.seq), Some(2));

    // A new connect dials B, never A.
    let res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("reconnect");
    assert_eq!(res.route.addr, b);
    assert!(res.failures.iter().all(|f| f.hint != a));
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_announced_routes_replace_stale_routes() {
    announced_routes_replace_stale_ones(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_announced_routes_replace_stale_routes() {
    announced_routes_replace_stale_ones(Wire::V2).await;
}

async fn committed_only_negotiates_no_route_sets(wire: Wire) {
    let me = Arc::new(identity(0x53));
    let (host, mut rx) = Host::new(0x63, wire, &me);
    let a = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, std::slice::from_ref(&a), 1);
    let store = RosterAccess::memory(roster);
    let mut o = opts();
    o.policy = RoutePolicy::CommittedOnly;

    let mut res = connect(wire, &me, &host.id(), &store, o)
        .await
        .expect("connect");
    let session = rx.recv().await.expect("host session");
    assert_eq!(session.peer_route_seq(), None);
    let err = session
        .sink()
        .send_route_set(&host.route_set(5, &[direct(1)]))
        .await
        .expect_err("not negotiated");
    assert!(
        matches!(err, RuntimeError::Core(CoreError::NotReady(m)) if m == "peer did not negotiate route sets"),
        "the sink passes the core error through unchanged"
    );
    session
        .send_data(b"open")
        .await
        .expect("session stays open");
    let client_roster = Mutex::new(store.load().unwrap());
    assert_eq!(
        res.session.next_event(&client_roster).await,
        Some(SessionEvent::AppData(b"open".to_vec()))
    );
    assert_eq!(routes(&store, &host.id(), RouteSource::Signed), vec![a]);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_committed_only_client_negotiates_no_route_sets() {
    committed_only_negotiates_no_route_sets(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_committed_only_client_negotiates_no_route_sets() {
    committed_only_negotiates_no_route_sets(Wire::V2).await;
}

async fn recovery_uri_rules(wire: Wire) {
    let me = Arc::new(identity(0x54));
    let (host, _rx) = Host::new(0x64, wire, &me);
    let live = direct(host.serve().await);
    let fresh = direct(host.serve().await);

    // An invalid statement fails before session msg3 on every candidate.
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, std::slice::from_ref(&live), 3);
    let store = RosterAccess::memory(roster.clone());
    let good = host.signed_uri_string(std::slice::from_ref(&fresh), 7);
    let mut sig: Vec<char> = good.chars().collect();
    let last = sig.len() - 2;
    sig[last] = if sig[last] == 'A' { 'B' } else { 'A' };
    let mut o = opts();
    o.recovery_uri = Some(sig.into_iter().collect());
    let err = connect(wire, &me, &host.id(), &store, o)
        .await
        .err()
        .expect("invalid rs");
    assert!(
        matches!(&err.error, RuntimeError::Core(CoreError::InvalidPairingUri(m)) if m == "route statement does not verify"),
        "{err}"
    );
    assert_eq!(
        host.established.load(Ordering::SeqCst),
        0,
        "host saw no msg3"
    );
    assert_eq!(
        routes(&store, &host.id(), RouteSource::Signed),
        vec![live.clone()]
    );

    // A fresh `rq` replaces the signed routes under allSigned.
    let mut o = opts();
    o.recovery_uri = Some(good);
    let res = connect(wire, &me, &host.id(), &store, o)
        .await
        .expect("fresh");
    assert_eq!(res.recovery_routes, Some(RecoveryRoutes::Replaced));
    assert_eq!(
        routes(&store, &host.id(), RouteSource::Signed),
        vec![fresh.clone()]
    );

    // A stale `rq` changes nothing without approval, and approval keeps max(seq).
    let stale = host.signed_uri_string(std::slice::from_ref(&live), 5);
    let mut o = opts();
    o.recovery_uri = Some(stale.clone());
    let res = connect(wire, &me, &host.id(), &store, o)
        .await
        .expect("stale");
    assert_eq!(
        res.recovery_routes,
        Some(RecoveryRoutes::Unchanged("stale_route_seq"))
    );
    assert_eq!(routes(&store, &host.id(), RouteSource::Signed), vec![fresh]);
    let mut o = opts();
    o.recovery_uri = Some(stale);
    o.replace_routes = true;
    let res = connect(wire, &me, &host.id(), &store, o)
        .await
        .expect("approved");
    assert_eq!(res.recovery_routes, Some(RecoveryRoutes::Approved));
    assert_eq!(routes(&store, &host.id(), RouteSource::Signed), vec![live]);
    let meta = store
        .load()
        .unwrap()
        .get(&host.id())
        .unwrap()
        .route_meta
        .unwrap();
    assert_eq!((meta.seq, meta.origin), (7, RouteOrigin::Approved));
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_recovery_uri_checks_rs_and_applies_rq_rules() {
    recovery_uri_rules(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_recovery_uri_checks_rs_and_applies_rq_rules() {
    recovery_uri_rules(Wire::V2).await;
}

async fn recovery_candidates_when_routes_are_empty(wire: Wire) {
    let me = Arc::new(identity(0x55));
    let (host, _rx) = Host::new(0x65, wire, &me);
    let live = direct(host.serve().await);
    let store = RosterAccess::memory(client_roster(&host));

    let mut o = opts();
    o.recovery_uri = Some(host.signed_uri_string(std::slice::from_ref(&live), 2));
    let res = connect(wire, &me, &host.id(), &store, o)
        .await
        .expect("recovery hint");
    assert_eq!(res.route.addr, live);
    assert_eq!(res.recovery_routes, Some(RecoveryRoutes::Replaced));

    let (other, _rx2) = Host::new(0x66, wire, &me);
    let other_live = direct(other.serve().await);
    let store = RosterAccess::memory(client_roster(&other));
    let mut o = opts();
    o.recovery_uri = Some(other.base_uri(&[other_live]).try_encode().unwrap());
    let err = connect(wire, &me, &other.id(), &store, o)
        .await
        .err()
        .expect("unsigned recovery adds nothing");
    assert!(
        err.to_string().contains("no dialable stored routes"),
        "{err}"
    );
    assert_eq!(other.preambles.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_signed_recovery_hints_are_candidates_when_routes_are_empty() {
    recovery_candidates_when_routes_are_empty(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_signed_recovery_hints_are_candidates_when_routes_are_empty() {
    recovery_candidates_when_routes_are_empty(Wire::V2).await;
}

async fn recovery_uri_for_another_host_fails_with_an_explicit_endpoint(wire: Wire) {
    let me = Arc::new(identity(0x56));
    let (host, _rx) = Host::new(0x67, wire, &me);
    let (other, _rx2) = Host::new(0x68, wire, &me);
    let live = direct(host.serve().await);
    let roster = client_roster(&host);
    let store = RosterAccess::memory(roster.clone());
    let mut uri = other.base_uri(&[]);
    uri.host_id = None;
    let mut o = opts();
    o.operator_endpoint = Some(live.clone());
    o.recovery_uri = Some(uri.try_encode().unwrap());

    let err = connect(wire, &me, &host.id(), &store, o)
        .await
        .err()
        .expect("wrong host keys");
    assert!(
        matches!(err.error, RuntimeError::Core(CoreError::HostKeyUnverified)),
        "{err}"
    );
    assert_eq!(host.established.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.load().unwrap().get(&host.id()),
        roster.get(&host.id()),
        "roster unchanged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_recovery_uri_for_another_host_fails_before_msg3_with_an_explicit_endpoint() {
    recovery_uri_for_another_host_fails_with_an_explicit_endpoint(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_recovery_uri_for_another_host_fails_before_msg3_with_an_explicit_endpoint() {
    recovery_uri_for_another_host_fails_with_an_explicit_endpoint(Wire::V2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_floor_raised_during_the_race_fails_the_final_check() {
    let me = Arc::new(identity(0x57));
    let (mut host, _rx) = Host::new(0x69, Wire::V1, &me);
    host.delay = Duration::from_millis(400);
    let live = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), std::slice::from_ref(&live));
    let store = RosterAccess::memory(roster);

    let target = host.id();
    let task = {
        let (me, store, target) = (Arc::clone(&me), store.clone(), target.clone());
        tokio::spawn(async move { connect(Wire::V1, &me, &target, &store, opts()).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    store
        .update(|r| {
            r.set_peer_min_wire_version(&target, 2)?;
            Ok(())
        })
        .unwrap();
    let err = task.await.unwrap().err().expect("final check");
    assert!(
        matches!(
            err.error,
            RuntimeError::Core(CoreError::VersionDowngrade { .. })
        ),
        "{err}"
    );
}

/// Accepts TCP, records when the first Tendril preamble arrived, and never answers.
async fn blackhole() -> (u16, Arc<Mutex<Option<Instant>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let first = Arc::new(Mutex::new(None));
    let first_c = Arc::clone(&first);
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let first = Arc::clone(&first_c);
            tokio::spawn(async move {
                let mut buf = [0u8; 3];
                if conn.read_exact(&mut buf).await.is_ok() && &buf == b"TND" {
                    first.lock().unwrap().get_or_insert_with(Instant::now);
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    (port, first)
}

/// Counts WebSocket upgrades to `/v1/relay` (foreign `GET /` probes are not counted).
async fn relay_spy() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let count_c = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let count = Arc::clone(&count_c);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 512];
                if let Ok(n) = conn.read(&mut buf).await
                    && buf[..n].starts_with(b"GET /v1/relay")
                {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    (format!("ws://127.0.0.1:{port}/v1/relay"), count)
}

fn ms_between(a: Instant, b: Instant) -> u128 {
    b.saturating_duration_since(a).as_millis()
}

async fn day2_ladder_staggers_overlay_then_relay(wire: Wire) {
    let me = Arc::new(identity(0x58));
    let (host, _rx) = Host::new(0x6A, wire, &me);

    // Blackhole direct, live overlay, relay: overlay wins and the relay is never dialed.
    let (hole, hole_first) = blackhole().await;
    let overlay = format!("overlay://127.0.0.1:{}", host.serve().await);
    let (relay_url, relay_dials) = relay_spy().await;
    let mut roster = client_roster(&host);
    set_operator(
        &mut roster,
        &host.id(),
        &[direct(hole), overlay.clone(), relay_url],
    );
    let store = RosterAccess::memory(roster);
    let res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("connect");
    assert_eq!(res.route.addr, overlay);
    let t_direct = hole_first.lock().unwrap().expect("direct dialed");
    let t_overlay = host.first_preamble.lock().unwrap().expect("overlay dialed");
    let gap = ms_between(t_direct, t_overlay);
    assert!(
        (230..=400).contains(&gap),
        "overlay started {gap} ms after direct"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay_dials.load(Ordering::SeqCst), 0, "relay never dialed");

    // Blackhole direct and overlay: the relay starts at about 500 ms and wins.
    let (hole_a, first_a) = blackhole().await;
    let (hole_b, _first_b) = blackhole().await;
    let relay = EmbeddedRelay::start(RelayConfig {
        host: "127.0.0.1".to_owned(),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let relay_listener = RelayListener::bind(
        relay.ws_url(),
        None,
        host.identity.signing_key().ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .unwrap();
    let relay_host = Host {
        first_preamble: Arc::new(Mutex::new(None)),
        ..host.clone()
    };
    relay_host.serve_on(Box::new(relay_listener));
    let mut roster = client_roster(&host);
    set_operator(
        &mut roster,
        &host.id(),
        &[
            direct(hole_a),
            format!("overlay://127.0.0.1:{hole_b}"),
            relay.ws_url(),
        ],
    );
    let store = RosterAccess::memory(roster);
    let res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("connect over relay");
    assert_eq!(res.route.provider, ProviderId::Relay);
    let t_direct = first_a.lock().unwrap().expect("direct dialed");
    let t_relay = relay_host
        .first_preamble
        .lock()
        .unwrap()
        .expect("relay used");
    let gap = ms_between(t_direct, t_relay);
    assert!(
        (450..=900).contains(&gap),
        "relay started {gap} ms after direct"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_day2_ladder_staggers_overlay_then_relay() {
    day2_ladder_staggers_overlay_then_relay(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_day2_ladder_staggers_overlay_then_relay() {
    day2_ladder_staggers_overlay_then_relay(Wire::V2).await;
}

/// A2 through the host announcer: the host's address changes from A to B between sessions; the
/// next session registers with the announcer, which sends the newer set as its first
/// host-initiated frame, and the client replaces A with B (operator routes kept).
async fn announcer_delivers_address_change(wire: Wire) {
    let me = Arc::new(identity(0x59));
    let (host, mut rx) = Host::new(0x6B, wire, &me);
    let a_port = host.serve().await;
    let b_port = host.serve().await;
    let explicit = |port: u16| AdvertiseInputs {
        mode: AdvertiseMode::Explicit,
        advertised_endpoints: vec![format!("127.0.0.1:{port}")],
        ..AdvertiseInputs::default()
    };
    let announcer = RouteAnnouncer::new(
        (*host.identity).clone(),
        RosterAccess::new(None, Arc::clone(&host.roster)),
        explicit(a_port),
        AddressSource::Native,
    );
    let first = announcer.publish(now() * 1000).expect("publish A");
    assert_eq!(first.routes(), [direct(a_port)]);

    let o = direct(dead_port().await);
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, first.routes(), first.seq());
    set_operator(&mut roster, &host.id(), std::slice::from_ref(&o));
    let store = RosterAccess::memory(roster);

    announcer.set_inputs(explicit(b_port));
    let second = announcer
        .refresh(now() * 1000, None)
        .expect("refresh to B")
        .state;
    assert_eq!(second.seq(), first.seq() + 1);

    let mut res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("connect over A");
    assert_eq!(res.route.addr, direct(a_port));
    let session = rx.recv().await.expect("host session");
    announcer
        .on_session_established(&session.sink(), session.peer_route_seq(), now() * 1000)
        .await
        .expect("register");
    session.send_data(b"after").await.expect("data");
    let client_roster = Mutex::new(store.load().unwrap());
    assert_eq!(
        res.session.next_event(&client_roster).await,
        Some(SessionEvent::AppData(b"after".to_vec()))
    );

    assert_eq!(
        routes(&store, &host.id(), RouteSource::Signed),
        vec![direct(b_port)]
    );
    assert_eq!(routes(&store, &host.id(), RouteSource::Operator), vec![o]);
    let res = connect(wire, &me, &host.id(), &store, opts())
        .await
        .expect("connect over B");
    assert_eq!(res.route.addr, direct(b_port));
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_announcer_delivers_a_host_address_change() {
    announcer_delivers_address_change(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_announcer_delivers_a_host_address_change() {
    announcer_delivers_address_change(Wire::V2).await;
}

fn tampered(uri: &str) -> String {
    let mut chars: Vec<char> = uri.chars().collect();
    let last = chars.len() - 2;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

fn racing_opts() -> ConnectOpts {
    let mut o = opts();
    o.policy_config.happy_eyeballs_stagger_ms = 0;
    o
}

fn host_crl(host: &Host, seq: u64, revoked: &str) -> RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host.id(),
            seq,
            revoked_devices: vec![revoked.to_owned()],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        host.identity.signing_key(),
    )
    .expect("crl")
}

async fn invalid_recovery_rs_is_never_masked(wire: Wire) {
    let me = Arc::new(identity(0x5A));
    let (mut host, _rx) = Host::new(0x6C, wire, &me);
    let (other, _rx2) = Host::new(0x6D, wire, &me);
    // The wrong host fails first with `HostKeyUnverified`, which ranks above
    // `InvalidPairingUri` among candidate errors.
    host.delay = Duration::from_millis(200);
    let wrong = direct(other.serve().await);
    let genuine = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), &[wrong, genuine.clone()]);
    let store = RosterAccess::memory(roster);
    let mut o = racing_opts();
    o.recovery_uri = Some(tampered(&host.signed_uri_string(&[genuine], 7)));

    let err = connect(wire, &me, &host.id(), &store, o)
        .await
        .err()
        .expect("invalid rs");
    assert!(
        matches!(&err.error, RuntimeError::Core(CoreError::InvalidPairingUri(m)) if m == "route statement does not verify"),
        "{err}"
    );
    assert_eq!(
        host.established.load(Ordering::SeqCst),
        0,
        "no session msg3"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_invalid_recovery_rs_is_fatal_and_never_masked() {
    invalid_recovery_rs_is_never_masked(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_invalid_recovery_rs_is_fatal_and_never_masked() {
    invalid_recovery_rs_is_never_masked(Wire::V2).await;
}

async fn pre_dial_gate_dials_nothing(wire: Wire) {
    let me = Arc::new(identity(0x5B));
    let (host, _rx) = Host::new(0x6E, wire, &me);
    let live = direct(host.serve().await);
    let spy = SpyDialer::default();
    let explicit = || {
        let mut o = spy.opts(opts());
        o.operator_endpoint = Some(live.clone());
        o
    };

    // Pending: an explicit endpoint would dial without the gate.
    let mut roster = Roster::new();
    roster
        .record_pending_host(
            host.id(),
            "Studio".into(),
            *host.identity.static_key().public_bytes(),
            host.identity.signing_key().public_key().clone(),
            0,
            "1234".into(),
            Vec::new(),
        )
        .unwrap();
    let err = connect(
        wire,
        &me,
        &host.id(),
        &RosterAccess::memory(roster),
        explicit(),
    )
    .await
    .err()
    .expect("pending");
    assert!(
        matches!(err.error, RuntimeError::Core(CoreError::PeerPending(_))),
        "{err}"
    );

    // Active but revoked by a CRL.
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), std::slice::from_ref(&live));
    let device = roster.get(&host.id()).unwrap().device_id.clone();
    roster
        .ingest_crl(
            host_crl(&host, 1, &device),
            &host.id(),
            host.identity.signing_key().public_key(),
        )
        .unwrap();
    let err = connect(
        wire,
        &me,
        &host.id(),
        &RosterAccess::memory(roster),
        spy.opts(opts()),
    )
    .await
    .err()
    .expect("crl revoked");
    assert!(
        matches!(err.error, RuntimeError::Core(CoreError::PeerRevoked(_))),
        "{err}"
    );

    if wire == Wire::V2 {
        // A Wire v2 connect to a peer without v2 secrets.
        let mut roster = client_roster_for(&host.identity, Wire::V1);
        set_operator(&mut roster, &host.id(), std::slice::from_ref(&live));
        let err = connect(
            wire,
            &me,
            &host.id(),
            &RosterAccess::memory(roster),
            spy.opts(opts()),
        )
        .await
        .err()
        .expect("no v2 secrets");
        assert!(
            matches!(err.error, RuntimeError::Core(CoreError::IncompletePin(_))),
            "{err}"
        );
    }
    assert_eq!(spy.dials.load(Ordering::SeqCst), 0, "zero dials");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(host.preambles.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_pre_dial_gate_dials_nothing() {
    pre_dial_gate_dials_nothing(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_pre_dial_gate_dials_nothing() {
    pre_dial_gate_dials_nothing(Wire::V2).await;
}

async fn revoked_during_the_race_fails_the_final_check(wire: Wire) {
    let me = Arc::new(identity(0x5C));
    let (mut host, _rx) = Host::new(0x6F, wire, &me);
    host.delay = Duration::from_millis(400);
    let live = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), std::slice::from_ref(&live));
    let store = RosterAccess::memory(roster);

    let target = host.id();
    let task = {
        let (me, store, target) = (Arc::clone(&me), store.clone(), target.clone());
        tokio::spawn(async move { connect(wire, &me, &target, &store, opts()).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    store
        .update(|r| {
            r.revoke_peer(&target)?;
            Ok(())
        })
        .unwrap();
    let err = task.await.unwrap().err().expect("final check");
    assert!(
        matches!(err.error, RuntimeError::Core(CoreError::PeerRevoked(_))),
        "{err}"
    );
    assert!(
        err.committed,
        "a session was established before the final check"
    );
    assert!(!err.is_transient_precommit());
    assert_eq!(
        host.preambles.load(Ordering::SeqCst),
        1,
        "revoked after the dial"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_revocation_during_the_race_fails_the_final_check() {
    revoked_during_the_race_fails_the_final_check(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_revocation_during_the_race_fails_the_final_check() {
    revoked_during_the_race_fails_the_final_check(Wire::V2).await;
}

/// How the two rotation forks of one pinned host take part in a connect. A candidate fails
/// right after its `HostHello` verified when the connect's recovery URI names other keys.
#[derive(Clone, Copy, Debug)]
enum ForkCase {
    /// Fork A wins (after a delay); fork B presents its `HostHello` first, then fails.
    AWins,
    /// The other order: fork B wins, fork A presents first and fails.
    BWins,
    /// Both forks present `HostHello` and fail: the connect is exhausted.
    Exhausted,
}

async fn rotation_fork_revokes_the_peer(wire: Wire, case: ForkCase) {
    let me = Arc::new(identity(0x5D));
    let base = identity(0x70);
    let (mut fork_a, _rx_a) = Host::with_identity(rotated(&base, 0xA1), wire, &me);
    let (mut fork_b, _rx_b) = Host::with_identity(rotated(&base, 0xB1), wire, &me);
    let (third, _rx_c) = Host::with_identity(rotated(&base, 0xD1), wire, &me);
    let winner_delay = Duration::from_millis(300);
    let expected = match case {
        ForkCase::AWins => {
            fork_a.delay = winner_delay;
            &fork_a
        }
        ForkCase::BWins => {
            fork_b.delay = winner_delay;
            &fork_b
        }
        ForkCase::Exhausted => &third,
    };
    let recovery = expected.base_uri(&[]).try_encode().unwrap();
    let a = direct(fork_a.serve().await);
    let b = direct(fork_b.serve().await);
    let mut roster = client_roster_for(&base, wire);
    set_operator(&mut roster, base.host_id(), &[a, b]);
    let store = RosterAccess::memory(roster);
    let mut o = racing_opts();
    o.recovery_uri = Some(recovery);

    let err = connect(wire, &me, base.host_id(), &store, o)
        .await
        .err()
        .expect("fork");
    assert!(
        matches!(
            err.error,
            RuntimeError::Core(CoreError::RotationForkDetected { .. })
        ),
        "{case:?}: {err}"
    );
    assert_eq!(
        fork_a.preambles.load(Ordering::SeqCst) + fork_b.preambles.load(Ordering::SeqCst),
        2,
        "{case:?}: both forks were raced"
    );
    assert_eq!(
        store.load().unwrap().get(base.host_id()).unwrap().state,
        PeerState::Revoked,
        "{case:?}: the fork revocation is persisted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_rotation_fork_is_detected_in_both_orders_and_on_exhaustion() {
    for case in [ForkCase::AWins, ForkCase::BWins, ForkCase::Exhausted] {
        rotation_fork_revokes_the_peer(Wire::V1, case).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_rotation_fork_is_detected_in_both_orders_and_on_exhaustion() {
    for case in [ForkCase::AWins, ForkCase::BWins, ForkCase::Exhausted] {
        rotation_fork_revokes_the_peer(Wire::V2, case).await;
    }
}

async fn relay_listener_for(host: &Host, relay: &EmbeddedRelay) {
    let listener = RelayListener::bind(
        relay.ws_url(),
        None,
        host.identity.signing_key().ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .unwrap();
    host.serve_on(Box::new(listener));
}

async fn local_relay() -> EmbeddedRelay {
    EmbeddedRelay::start(RelayConfig {
        host: "127.0.0.1".to_owned(),
        ..RelayConfig::default()
    })
    .await
    .unwrap()
}

fn pinned_signing(store: &RosterAccess, peer: &str) -> (Option<Vec<u8>>, u64) {
    let roster = store.load().unwrap();
    let entry = roster.get(peer).unwrap();
    (
        entry
            .signing_pub
            .as_ref()
            .map(|k| k.ed25519_bytes().to_vec()),
        entry.rotation_seq,
    )
}

async fn rotation_recovery(wire: Wire) {
    let me = Arc::new(identity(0x5E));
    let base = identity(0x71);
    let (host, _rx) = Host::with_identity(rotated(&base, 0xC1), wire, &me);
    let new_key = host
        .identity
        .signing_key()
        .public_key()
        .ed25519_bytes()
        .to_vec();
    let relay = local_relay().await;
    relay_listener_for(&host, &relay).await;
    let relay_url = relay.ws_url();

    // A relay-only peer pinned to the old key reaches an offline mailbox: typed fast failure.
    let mut roster = client_roster_for(&base, wire);
    set_operator(
        &mut roster,
        base.host_id(),
        std::slice::from_ref(&relay_url),
    );
    let store = RosterAccess::memory(roster.clone());
    let err = connect(wire, &me, base.host_id(), &store, opts())
        .await
        .err()
        .expect("offline mailbox");
    assert!(
        err.to_string()
            .contains("relay mailbox offline for pinned key; host may have rotated"),
        "{err}"
    );
    assert!(err.error.is_relay_offline(), "{err:?}");
    assert!(err.failures.iter().all(|f| f.error.is_relay_offline()));
    assert!(
        err.is_wakeable_miss() && !err.is_transient_precommit(),
        "{err}"
    );
    assert_eq!(host.established.load(Ordering::SeqCst), 0);

    // A fresh URI signed by the rotated key: its `rp` selects the new mailbox, the chain
    // verifies, the pin advances and the routes are applied.
    let mut o = opts();
    o.recovery_uri = Some(host.signed_uri_string(std::slice::from_ref(&relay_url), 2));
    let res = connect(wire, &me, base.host_id(), &store, o)
        .await
        .expect("recovery with rp");
    assert_eq!(res.route.addr, relay_url);
    assert_eq!(res.recovery_routes, Some(RecoveryRoutes::Replaced));
    assert_eq!(
        pinned_signing(&store, base.host_id()),
        (Some(new_key.clone()), 1)
    );

    // Alternate path: a live direct route applies the rotation; later relay dials use the new
    // key without a recovery URI.
    let live = direct(host.serve().await);
    let mut roster = client_roster_for(&base, wire);
    set_operator(
        &mut roster,
        base.host_id(),
        &[relay_url.clone(), live.clone()],
    );
    let store = RosterAccess::memory(roster);
    let res = connect(wire, &me, base.host_id(), &store, opts())
        .await
        .expect("alternate direct");
    assert_eq!(res.route.addr, live);
    assert_eq!(pinned_signing(&store, base.host_id()), (Some(new_key), 1));
    store
        .update(|r| {
            set_operator(r, base.host_id(), std::slice::from_ref(&relay_url));
            Ok(())
        })
        .unwrap();
    let res = connect(wire, &me, base.host_id(), &store, opts())
        .await
        .expect("relay under the new key");
    assert_eq!(res.route.addr, relay_url);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_rotation_recovery_with_rp_relay_fast_fail_and_alternate_direct() {
    rotation_recovery(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_rotation_recovery_with_rp_relay_fast_fail_and_alternate_direct() {
    rotation_recovery(Wire::V2).await;
}

async fn rotated_host_reached_only_through_its_qr(wire: Wire) {
    let me = Arc::new(identity(0x5F));
    let base = identity(0x72);
    let (host, _rx) = Host::with_identity(rotated(&base, 0xC3), wire, &me);
    let live = direct(host.serve().await);
    let mut roster = client_roster_for(&base, wire);
    set_operator(&mut roster, base.host_id(), &[direct(dead_port().await)]);
    let store = RosterAccess::memory(roster);

    let mut o = opts();
    o.recovery_uri = Some(host.signed_uri_string(std::slice::from_ref(&live), 3));
    let res = connect(wire, &me, base.host_id(), &store, o)
        .await
        .expect("the QR hint is the only live route");
    assert_eq!(res.route.addr, live);
    assert_eq!(res.recovery_routes, Some(RecoveryRoutes::Replaced));
    assert_eq!(
        routes(&store, base.host_id(), RouteSource::Signed),
        vec![live]
    );
    assert_eq!(
        pinned_signing(&store, base.host_id()),
        (
            Some(
                host.identity
                    .signing_key()
                    .public_key()
                    .ed25519_bytes()
                    .to_vec()
            ),
            1
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_rotated_host_reached_only_through_its_signed_qr() {
    rotated_host_reached_only_through_its_qr(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_rotated_host_reached_only_through_its_signed_qr() {
    rotated_host_reached_only_through_its_qr(Wire::V2).await;
}

async fn announcement_after_rotation(wire: Wire) {
    let me = Arc::new(identity(0x60));
    let base = identity(0x73);
    let (host, mut rx) = Host::with_identity(rotated(&base, 0xC5), wire, &me);
    let (before_rotation, _rx_old) = Host::with_identity(base.clone(), wire, &me);
    let a = direct(host.serve().await);
    let b = direct(host.serve().await);
    let mut roster = client_roster_for(&base, wire);
    set_signed(&mut roster, &before_rotation, std::slice::from_ref(&a), 1);
    let store = RosterAccess::memory(roster);

    let mut res = connect(wire, &me, base.host_id(), &store, opts())
        .await
        .expect("connect over a direct route");
    let session = rx.recv().await.expect("host session");
    session
        .sink()
        .send_route_set(&host.route_set(2, std::slice::from_ref(&b)))
        .await
        .expect("route set under the new key");
    session.send_data(b"after").await.expect("data");
    let client_roster = Mutex::new(store.load().unwrap());
    assert_eq!(
        res.session.next_event(&client_roster).await,
        Some(SessionEvent::AppData(b"after".to_vec()))
    );
    assert_eq!(
        store.last_route_set(base.host_id()).map(|l| l.outcome),
        Some("applied")
    );
    assert_eq!(routes(&store, base.host_id(), RouteSource::Signed), vec![b]);
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_announcement_after_rotation_applies_under_the_new_key() {
    announcement_after_rotation(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_announcement_after_rotation_applies_under_the_new_key() {
    announcement_after_rotation(Wire::V2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_recovery_relay_v2_hint_is_gated_then_dialed() {
    let me = Arc::new(identity(0x61));
    let (host, _rx) = Host::new(0x74, Wire::V2, &me);
    let relay = local_relay().await;
    let v2_url = relay.ws_v2_url();
    let listener = RelayV2Listener::bind(
        &v2_url,
        None,
        *secrets().mailbox_secret(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .unwrap();
    host.serve_on(Box::new(listener));
    let live = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), std::slice::from_ref(&live));
    let store = RosterAccess::memory(roster);

    // The recovery hint is not yet a stored route: gated before any derivation.
    let mut o = opts();
    o.recovery_uri = Some(host.signed_uri_string(std::slice::from_ref(&v2_url), 4));
    let res = connect(Wire::V2, &me, &host.id(), &store, o)
        .await
        .expect("connect over the operator route");
    assert_eq!(res.route.addr, live);
    assert!(
        res.skipped
            .iter()
            .any(|s| s.hint == v2_url && s.reason == SkipReason::RelayV2NotAuthorized),
        "{:?}",
        res.skipped
    );
    assert_eq!(res.recovery_routes, Some(RecoveryRoutes::Replaced));
    assert_eq!(
        routes(&store, &host.id(), RouteSource::Signed),
        vec![v2_url.clone()]
    );
    assert_eq!(
        host.preambles.load(Ordering::SeqCst),
        1,
        "only the direct dial"
    );

    // Now a signed route of this entry: the next connect derives the mailbox and dials it.
    store
        .update(|r| {
            r.clear_routes(&host.id(), Some(RouteSource::Operator))?;
            Ok(())
        })
        .unwrap();
    let res = connect(Wire::V2, &me, &host.id(), &store, opts())
        .await
        .expect("connect over /v2/relay");
    assert_eq!(res.route.addr, v2_url);
    assert_eq!(host.preambles.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_concurrent_sink_passes_frame_too_large_through() {
    let me = Arc::new(identity(0x62));
    let (mut host, mut rx) = Host::new(0x75, Wire::V2, &me);
    host.v2_state = Arc::new(V2ResponderState::with_config(V2ResponderConfig {
        padding: PaddingPolicy::with_buckets(vec![256, 1_024], true).unwrap(),
        ..V2ResponderConfig::default()
    }));
    let live = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, std::slice::from_ref(&live), 1);
    let store = RosterAccess::memory(roster);

    let mut res = connect(Wire::V2, &me, &host.id(), &store, opts())
        .await
        .expect("connect");
    let session = rx.recv().await.expect("host session");
    let err = session
        .sink()
        .send_route_set(&host.route_set(2, std::slice::from_ref(&live)))
        .await
        .expect_err("no bucket fits");
    assert!(
        matches!(err, RuntimeError::Core(CoreError::FrameTooLarge { .. })),
        "the sink passes the core error through unchanged: {err}"
    );
    session
        .send_data(b"open")
        .await
        .expect("session stays open");
    let client_roster = Mutex::new(store.load().unwrap());
    assert_eq!(
        res.session.next_event(&client_roster).await,
        Some(SessionEvent::AppData(b"open".to_vec()))
    );
}

async fn crl_survives_a_concurrent_route_ingest(wire: Wire) {
    let me = Arc::new(identity(0x63));
    let (host, mut rx) = Host::new(0x76, wire, &me);
    let a = direct(host.serve().await);
    let b = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, std::slice::from_ref(&a), 1);
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(StateStore::open_or_create(dir.path()).unwrap());
    state.save_roster(&roster).unwrap();
    let access = RosterAccess::from_store(Arc::clone(&state)).unwrap();

    let mut res = connect(wire, &me, &host.id(), &access, opts())
        .await
        .expect("connect");
    let session = rx.recv().await.expect("host session");
    let crl = host_crl(&host, 3, "unrelated-device");
    match &session {
        HostSession::V1(s) => s.send_revocation(&crl).await.expect("crl"),
        HostSession::V2(s) => s.send_revocation(&crl).await.expect("crl"),
    }
    session
        .sink()
        .send_route_set(&host.route_set(2, std::slice::from_ref(&b)))
        .await
        .expect("route set");
    session.send_data(b"after").await.expect("data");

    // The endpoint's in-memory roster is the handle's own copy.
    let memory = Arc::clone(access.roster());
    assert_eq!(
        res.session.next_event(&memory).await,
        Some(SessionEvent::RevocationUpdated {
            issuer: host.id(),
            seq: 3
        })
    );
    assert_eq!(
        res.session.next_event(&memory).await,
        Some(SessionEvent::AppData(b"after".to_vec()))
    );
    assert_eq!(routes(&access, &host.id(), RouteSource::Signed), vec![b]);
    assert_eq!(
        memory.lock().unwrap().crl(&host.id()).map(|c| c.seq),
        Some(3),
        "the route write did not drop the in-memory CRL"
    );
    assert_eq!(
        state.load_roster().unwrap().crl(&host.id()).map(|c| c.seq),
        Some(3),
        "the CRL was persisted with the route write"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_crl_survives_a_concurrent_route_ingest() {
    crl_survives_a_concurrent_route_ingest(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_crl_survives_a_concurrent_route_ingest() {
    crl_survives_a_concurrent_route_ingest(Wire::V2).await;
}

/// A `Direct` dialer counting its dials and the `close()` calls of its streams.
#[derive(Clone, Default)]
struct SpyDialer {
    dials: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

impl SpyDialer {
    fn opts(&self, mut o: ConnectOpts) -> ConnectOpts {
        o.dialers = Arc::new(
            HintDialers::new(HintDialerConfig::default())
                .with_provider_dialer(Arc::new(self.clone())),
        );
        o
    }
}

#[async_trait::async_trait]
impl PathDialer for SpyDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CloseCounting {
            inner: DirectDialer::new().dial(endpoint).await?,
            closes: Arc::clone(&self.closes),
        }))
    }
}

struct CloseCounting {
    inner: Box<dyn PathStream>,
    closes: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl PathStream for CloseCounting {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.inner.close().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        split_path_stream_fallback(self)
    }
}

async fn failed_candidate_is_closed_gracefully(wire: Wire) {
    let me = Arc::new(identity(0x64));
    let (mut host, _rx) = Host::new(0x77, wire, &me);
    let (other, _rx2) = Host::new(0x78, wire, &me);
    host.delay = Duration::from_millis(200);
    let wrong = direct(other.serve().await);
    let genuine = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), &[wrong.clone(), genuine.clone()]);
    let store = RosterAccess::memory(roster);
    let spy = SpyDialer::default();

    let res = connect(wire, &me, &host.id(), &store, spy.opts(racing_opts()))
        .await
        .expect("connect");
    assert_eq!(res.route.addr, genuine);
    assert!(
        res.failures.iter().any(|f| f.hint == wrong
            && matches!(f.error, RuntimeError::Core(CoreError::HostKeyUnverified))),
        "{:?}",
        res.failures
    );
    assert_eq!(
        spy.closes.load(Ordering::SeqCst),
        1,
        "the failed candidate's stream was closed, the winner's kept"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_failed_day2_candidate_is_closed_gracefully() {
    failed_candidate_is_closed_gracefully(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_failed_day2_candidate_is_closed_gracefully() {
    failed_candidate_is_closed_gracefully(Wire::V2).await;
}

async fn transient_precommit_classification(wire: Wire) {
    let me = Arc::new(identity(0x5D));
    let (host, _rx) = Host::new(0x71, wire, &me);
    let mut roster = client_roster(&host);
    set_operator(&mut roster, &host.id(), &[direct(dead_port().await)]);
    let store = RosterAccess::memory(roster);
    let err = connect(wire, &me, &host.id(), &store, opts())
        .await
        .err()
        .expect("dead route");
    assert!(!err.committed);
    assert!(
        err.is_transient_precommit(),
        "a refused dial is a transport miss: {err}"
    );

    let store = RosterAccess::memory(client_roster(&host));
    let err = connect(wire, &me, &host.id(), &store, opts())
        .await
        .err()
        .expect("no routes");
    assert!(!err.is_transient_precommit(), "no dialable routes: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_transient_precommit_is_only_an_uncommitted_transport_miss() {
    transient_precommit_classification(Wire::V1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_transient_precommit_is_only_an_uncommitted_transport_miss() {
    transient_precommit_classification(Wire::V2).await;
}

#[test]
fn transient_precommit_excludes_every_permanent_class() {
    let attempt = |error: RuntimeError, committed: bool| AttemptError {
        error,
        committed,
        skipped: Vec::new(),
        failures: Vec::new(),
    };
    let io = || RuntimeError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
    assert!(attempt(io(), false).is_transient_precommit());
    assert!(attempt(RuntimeError::Timeout("dial"), false).is_transient_precommit());
    assert!(attempt(RuntimeError::Closed, false).is_transient_precommit());
    assert!(!attempt(io(), true).is_transient_precommit());
    for error in [
        RuntimeError::Core(CoreError::PeerRevoked("p".into())),
        RuntimeError::Policy("all candidates exhausted"),
        RuntimeError::Protocol("relay_auth_unconfigured: relay requires credentials".into()),
        RuntimeError::Protocol("relay mailbox offline for pinned key".into()),
        RuntimeError::Protocol("no dialable stored routes for p".into()),
        RuntimeError::Storage("disk".into()),
        RuntimeError::Egress {
            reason: SkipReason::Unresolved,
            detail: "lookup failed".into(),
        },
    ] {
        assert!(!attempt(error, false).is_transient_precommit());
    }
    let mut mixed = attempt(io(), false);
    mixed.failures.push(tendril_runtime::CandidateFailure {
        hint: "wss://relay.example/v1/relay".into(),
        provider: ProviderId::Relay,
        error: RuntimeError::Protocol("relay_auth_unconfigured".into()),
    });
    assert!(
        !mixed.is_transient_precommit(),
        "one permanent candidate failure"
    );
}

/// The next event of `session`, driven directly or as a concurrent session, on `roster`.
async fn next_result(
    session: Client,
    concurrent: bool,
    roster: &Mutex<Roster>,
) -> Result<Option<SessionEvent>, RuntimeError> {
    let fut = async {
        match (session, concurrent) {
            (Client::V1(mut s), false) => s.next_event_locked_now(roster).await,
            (Client::V1(s), true) => s.into_concurrent().next_event_locked_now(roster).await,
            (Client::V2(mut s), false) => s.next_event_locked_now(roster).await,
            (Client::V2(s), true) => s.into_concurrent().next_event_locked_now(roster).await,
        }
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("event in time")
}

/// A CRL that revokes this device or the connected host ends the session with `PeerRevoked`,
/// and still reaches the endpoint's roster handle (and its store) through the client ingest.
/// The session feeds its own roster copy, so only the ingest can carry the CRL.
async fn revoking_crl_is_kept(wire: Wire, concurrent: bool) {
    for (i, revoke_me) in [true, false].into_iter().enumerate() {
        for stored in [true, false] {
            let me = Arc::new(identity(0x68));
            let tag = 0x79 + u8::try_from(i).unwrap() * 2 + u8::from(stored);
            let (host, mut rx) = Host::new(tag, wire, &me);
            let a = direct(host.serve().await);
            let mut roster = client_roster(&host);
            set_operator(&mut roster, &host.id(), std::slice::from_ref(&a));
            let dir = tempfile::tempdir().unwrap();
            let state = Arc::new(StateStore::open_or_create(dir.path()).unwrap());
            let access = if stored {
                state.save_roster(&roster).unwrap();
                RosterAccess::from_store(Arc::clone(&state)).unwrap()
            } else {
                RosterAccess::memory(roster)
            };

            let res = connect(wire, &me, &host.id(), &access, opts())
                .await
                .expect("connect");
            let session = rx.recv().await.expect("host session");
            let revoked = if revoke_me { me.device_id() } else { host.id() };
            let crl = host_crl(&host, 3, &revoked);
            match &session {
                HostSession::V1(s) => s.send_revocation(&crl).await.expect("crl"),
                HostSession::V2(s) => s.send_revocation(&crl).await.expect("crl"),
            }

            let feed = Mutex::new(access.load().unwrap());
            let err = next_result(res.session, concurrent, &feed)
                .await
                .expect_err("revoked session ends");
            assert!(
                matches!(err, RuntimeError::Core(CoreError::PeerRevoked(_))),
                "{err:?}"
            );
            let case = format!("revoke_me={revoke_me} stored={stored}");
            assert_eq!(
                access.load().unwrap().crl(&host.id()).map(|c| c.seq),
                Some(3),
                "{case}: the handle kept the CRL"
            );
            if stored {
                assert_eq!(
                    state.load_roster().unwrap().crl(&host.id()).map(|c| c.seq),
                    Some(3),
                    "{case}: the CRL was persisted"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_revoking_crl_is_kept_after_the_session_fails() {
    revoking_crl_is_kept(Wire::V1, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_concurrent_revoking_crl_is_kept_after_the_session_fails() {
    revoking_crl_is_kept(Wire::V1, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_revoking_crl_is_kept_after_the_session_fails() {
    revoking_crl_is_kept(Wire::V2, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_concurrent_revoking_crl_is_kept_after_the_session_fails() {
    revoking_crl_is_kept(Wire::V2, true).await;
}

#[test]
fn roster_load_merges_crls_held_in_memory() {
    let me = identity(0x69);
    let (host, _rx) = Host::new(0x7F, Wire::V1, &me);
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(StateStore::open_or_create(dir.path()).unwrap());
    state.save_roster(&client_roster(&host)).unwrap();
    let access = RosterAccess::from_store(Arc::clone(&state)).unwrap();
    access
        .roster()
        .lock()
        .unwrap()
        .ingest_crl(
            host_crl(&host, 4, "unrelated-device"),
            &host.id(),
            host.identity.signing_key().public_key(),
        )
        .unwrap();
    assert_eq!(
        access.load().unwrap().crl(&host.id()).map(|c| c.seq),
        Some(4)
    );
}

/// The client ingest persists through the roster file lock off the async workers: while
/// another holder keeps that lock, a single-threaded runtime still runs its other tasks.
async fn ingest_never_blocks_the_runtime(wire: Wire) {
    let me = Arc::new(identity(0x6A));
    let (host, mut rx) = Host::new(0x7E, wire, &me);
    let a = direct(host.serve().await);
    let mut roster = client_roster(&host);
    set_signed(&mut roster, &host, std::slice::from_ref(&a), 1);
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(StateStore::open_or_create(dir.path()).unwrap());
    state.save_roster(&roster).unwrap();
    let access = RosterAccess::from_store(Arc::clone(&state)).unwrap();
    let res = connect(wire, &me, &host.id(), &access, opts())
        .await
        .expect("connect");
    let session = rx.recv().await.expect("host session");

    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let holder = {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = state.update_roster(|_| -> Result<(), RuntimeError> {
                held_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(800));
                Err(RuntimeError::Storage("held".into()))
            });
        })
    };
    held_rx.recv().unwrap();
    session
        .sink()
        .send_route_set(&host.route_set(2, std::slice::from_ref(&a)))
        .await
        .expect("route set");
    session.send_data(b"after").await.expect("data");

    let max_gap = Arc::new(Mutex::new(Duration::ZERO));
    let ticker = {
        let max_gap = Arc::clone(&max_gap);
        tokio::spawn(async move {
            let mut last = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let gap = last.elapsed();
                last = Instant::now();
                let mut max = max_gap.lock().unwrap();
                *max = (*max).max(gap);
            }
        })
    };
    let memory = Arc::clone(access.roster());
    let ev = match res.session {
        Client::V1(s) => s.into_concurrent().next_event_locked_now(&memory).await,
        Client::V2(s) => s.into_concurrent().next_event_locked_now(&memory).await,
    };
    assert!(
        matches!(&ev, Ok(Some(SessionEvent::AppData(d))) if d == b"after"),
        "{ev:?}"
    );
    holder.join().unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    ticker.abort();
    let max = *max_gap.lock().unwrap();
    assert!(
        max < Duration::from_millis(400),
        "the runtime stalled for {max:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v1_route_ingest_never_blocks_the_runtime() {
    ingest_never_blocks_the_runtime(Wire::V1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn v2_route_ingest_never_blocks_the_runtime() {
    ingest_never_blocks_the_runtime(Wire::V2).await;
}

#[test]
fn wakeable_miss_adds_only_uncommitted_typed_relay_offline() {
    use tendril_runtime::RelayOffline;

    let attempt = |error: RuntimeError, committed: bool| AttemptError {
        error,
        committed,
        skipped: Vec::new(),
        failures: Vec::new(),
    };
    let failure = |error: RuntimeError| tendril_runtime::CandidateFailure {
        hint: "wss://relay.example/v1/relay".into(),
        provider: ProviderId::Relay,
        error,
    };
    let io = || RuntimeError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
    let offline = [
        (RelayOffline::V1Dial, "relay dial rejected: offline"),
        (RelayOffline::V2Dial, "v2 relay dial rejected: offline"),
        (
            RelayOffline::PinnedKey,
            "relay mailbox offline for pinned key; host may have rotated: reconnect over \
             another route or supply a fresh pairing URI",
        ),
    ];
    for (kind, text) in offline {
        let err = RuntimeError::RelayOffline(kind);
        assert_eq!(err.to_string(), text, "surfaces match this text");
        assert!(err.is_relay_offline());
        assert!(attempt(RuntimeError::RelayOffline(kind), false).is_wakeable_miss());
        assert!(!attempt(RuntimeError::RelayOffline(kind), false).is_transient_precommit());
        assert!(!attempt(RuntimeError::RelayOffline(kind), true).is_wakeable_miss());
    }
    for transient in [io(), RuntimeError::Timeout("dial"), RuntimeError::Closed] {
        assert!(attempt(transient, false).is_wakeable_miss());
    }
    assert!(!attempt(io(), true).is_wakeable_miss());

    let mut mixed = attempt(RuntimeError::RelayOffline(RelayOffline::PinnedKey), false);
    mixed
        .failures
        .push(failure(RuntimeError::RelayOffline(RelayOffline::V1Dial)));
    mixed.failures.push(failure(io()));
    assert!(mixed.is_wakeable_miss());
    mixed.failures.push(failure(RuntimeError::Protocol(
        "relay_auth_unconfigured".into(),
    )));
    assert!(!mixed.is_wakeable_miss(), "one permanent candidate failure");

    for error in [
        RuntimeError::Protocol("relay dial rejected: offline".into()),
        RuntimeError::Protocol("relay mailbox offline for pinned key".into()),
        RuntimeError::Core(CoreError::PeerRevoked("p".into())),
        RuntimeError::Policy("all candidates exhausted"),
        RuntimeError::Storage("disk".into()),
        RuntimeError::Egress {
            reason: SkipReason::Unresolved,
            detail: "lookup failed".into(),
        },
    ] {
        assert!(!attempt(error, false).is_wakeable_miss(), "never by text");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_and_v2_policy_connect_complete_over_standby_pool_and_fast_open() {
    let relay = local_relay().await;
    let me = Arc::new(identity(0x71));

    // Wire v1 over /v1/relay with RelayListener standby pool + fast_open init_frame.
    let (v1_host, mut v1_rx) = Host::new(0x81, Wire::V1, &me);
    let v1_url = relay.ws_url();
    let v1_listener = RelayListener::bind(
        &v1_url,
        None,
        v1_host.identity.signing_key().ed25519_signing_key().clone(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(v1_listener.active_standby_socket_count(), 2);
    v1_host.serve_on(Box::new(v1_listener));
    let mut v1_roster = client_roster(&v1_host);
    set_signed(&mut v1_roster, &v1_host, std::slice::from_ref(&v1_url), 1);
    let v1_store = RosterAccess::memory(v1_roster);
    let mut v1_res = connect(Wire::V1, &me, &v1_host.id(), &v1_store, opts())
        .await
        .expect("v1 connect over standby+fast_open");
    assert_eq!(v1_res.route.provider, ProviderId::Relay);
    assert_eq!(v1_res.route.addr, v1_url);
    let v1_sess = v1_rx.recv().await.expect("v1 host session");
    v1_sess.send_data(b"ping-v1").await.unwrap();
    let v1_cli_roster = Mutex::new(v1_store.load().unwrap());
    assert_eq!(
        v1_res.session.next_event(&v1_cli_roster).await,
        Some(SessionEvent::AppData(b"ping-v1".to_vec()))
    );

    // Wire v2 over /v2/relay with RelayV2Listener standby pool + fast_open init_frame.
    let (v2_host, mut v2_rx) = Host::new(0x82, Wire::V2, &me);
    let v2_url = relay.ws_v2_url();
    let v2_listener = RelayV2Listener::bind(
        &v2_url,
        None,
        *secrets().mailbox_secret(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(v2_listener.active_control_socket_count(), 3);
    assert_eq!(v2_listener.active_standby_socket_count(), 2);
    v2_host.serve_on(Box::new(v2_listener));
    let mut v2_roster = client_roster(&v2_host);
    set_signed(&mut v2_roster, &v2_host, std::slice::from_ref(&v2_url), 1);
    let v2_store = RosterAccess::memory(v2_roster);
    let mut v2_res = connect(Wire::V2, &me, &v2_host.id(), &v2_store, opts())
        .await
        .expect("v2 connect over standby+fast_open");
    assert_eq!(v2_res.route.addr, v2_url);
    let v2_sess = v2_rx.recv().await.expect("v2 host session");
    v2_sess.send_data(b"ping-v2").await.unwrap();
    let v2_cli_roster = Mutex::new(v2_store.load().unwrap());
    assert_eq!(
        v2_res.session.next_event(&v2_cli_roster).await,
        Some(SessionEvent::AppData(b"ping-v2".to_vec()))
    );
}
