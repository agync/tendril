//! Candidate builder, `/v2/relay` gate, relay adapter and credential gate, operator endpoint
//! normalization, peer route setter and offline signed URI application (`providers::hints`).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PairingCodeKind, PairingUri, RoutePolicy, is_v2_relay_hint, sign_route_statement,
};
use tendril_core::policy::{PathPolicyConfig, ProviderId};
use tendril_core::relay_auth::RelayAuthSecret;
use tendril_core::roster::{
    OperatorEndpoint, Roster, RouteMeta, RouteOrigin, RouteSource, StoredRoute, V2PeerSecrets,
};
use tendril_relay::protocol::{
    MAX_RELAY_FRAME_LEN, RelayClientMsg, RelayServerMsg, RelayV2ClientMsg, RelayV2ServerMsg,
};
use tendril_runtime::providers::egress::{
    EgressContext, EgressKind, HintSource, HostResolver, SkipReason,
};
use tendril_runtime::providers::hints::{
    CandidateSet, DialWire, HintDialerConfig, HintDialers, HintInput, HintTarget, MultiDialOptions,
    RelayV2Gate, RouteApplyOpts, apply_signed_route_uri, build_pairing_candidates,
    clear_peer_routes, clear_peer_routes_in, normalize_operator_endpoint, peer_routes,
    session_hint_inputs, set_peer_routes, set_peer_routes_in, stored_route_inputs,
};
use tendril_runtime::providers::relay::RelayHintDialer;
use tendril_runtime::{
    PathDialer, PathStream, RelayClientAuth, RosterAccess, RuntimeError, StateStore,
    dial_with_policy,
};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn owned(hints: &[&str]) -> Vec<String> {
    hints.iter().map(|h| (*h).to_owned()).collect()
}

fn ed_key(host: &EndpointIdentity) -> [u8; 32] {
    *host.signing_key().ed25519_public_bytes()
}

/// A roster holding an `Active` pin for `host` with legacy `relay_hints`.
fn client_of(host: &EndpointIdentity, relay_hints: &[&str]) -> (Roster, String) {
    let mut roster = Roster::new();
    let peer = host.host_id().to_owned();
    roster
        .insert_pinned_host(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            owned(relay_hints),
        )
        .expect("pin");
    (roster, peer)
}

fn signed_uri(host: &EndpointIdentity, hints: &[&str], rq: u64) -> PairingUri {
    let mut uri = PairingUri::new(
        "Studio",
        "TND-ABCD-EFGH-JKLM",
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        owned(hints),
        Some(host.host_id().to_owned()),
        Some(0),
    );
    if hints.iter().any(|h| h.contains("/v1/relay")) {
        uri.relay_pub = Some(ed_key(host));
    }
    let prefix = format!("{}&rq={rq}", uri.try_encode().expect("encode"));
    let sig = sign_route_statement(host, &prefix);
    PairingUri::parse(&format!("{prefix}&rs={}", b64url_encode(&sig))).expect("parse")
}

fn unsigned_uri(host: &EndpointIdentity, hints: &[&str]) -> PairingUri {
    let uri = PairingUri::new(
        "Studio",
        "TND-ABCD-EFGH-JKLM",
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        owned(hints),
        Some(host.host_id().to_owned()),
        Some(0),
    );
    PairingUri::parse(&uri.try_encode().expect("encode")).expect("parse")
}

fn routes_of(roster: &Roster, peer: &str, source: RouteSource) -> Vec<String> {
    roster
        .get(peer)
        .expect("entry")
        .routes_from(source)
        .map(str::to_owned)
        .collect()
}

struct NoResolver;

#[async_trait]
impl HostResolver for NoResolver {
    async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        Err(RuntimeError::Protocol(format!(
            "unexpected lookup of {host}"
        )))
    }
}

fn ctx(kind: EgressKind, origins: &[&str]) -> EgressContext {
    EgressContext::new(kind)
        .with_resolver(Arc::new(NoResolver))
        .with_relay_auth_origins(owned(origins))
}

fn opts(wire: DialWire, auth: RelayClientAuth) -> MultiDialOptions {
    let config = HintDialerConfig {
        relay_auth: auth,
        ..HintDialerConfig::default()
    };
    MultiDialOptions::new(Arc::new(HintDialers::new(config)), wire)
}

fn hmac_auth() -> RelayClientAuth {
    RelayClientAuth::HmacSecret(RelayAuthSecret::new(vec![0x5A; 32]).expect("secret"))
}

fn skip_of(set: &CandidateSet, hint: &str) -> Option<SkipReason> {
    set.skipped
        .iter()
        .find(|s| s.hint == hint)
        .map(|s| s.reason)
}

fn addrs(set: &CandidateSet) -> Vec<&str> {
    set.candidates.iter().map(|c| c.addr.as_str()).collect()
}

/// Wraps every dialer of a candidate set with a dial counter.
struct SpyDialer {
    inner: Arc<dyn PathDialer>,
    dials: Arc<AtomicUsize>,
}

#[async_trait]
impl PathDialer for SpyDialer {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        self.inner.dial(endpoint).await
    }
}

fn spied(set: &CandidateSet, dials: &Arc<AtomicUsize>) -> Vec<Arc<dyn PathDialer>> {
    set.dialers
        .iter()
        .map(|d| {
            Arc::new(SpyDialer {
                inner: Arc::clone(d),
                dials: Arc::clone(dials),
            }) as Arc<dyn PathDialer>
        })
        .collect()
}

#[tokio::test]
async fn legacy_relay_hints_never_become_candidates() {
    let host = identity(1);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let live = format!("direct:{}", listener.local_addr().expect("addr"));
    let (roster, peer) = client_of(&host, &[live.as_str(), "wss://relay.example/v1/relay"]);
    let entry = roster.get(&peer).expect("entry");
    assert_eq!(entry.relay_hints.len(), 2, "fixture holds legacy hints");

    let inputs = session_hint_inputs(entry, None, None);
    assert!(
        inputs.is_empty(),
        "legacy relay_hints are not inputs: {inputs:?}"
    );
    assert!(stored_route_inputs(entry).is_empty());

    let target = HintTarget::session(&peer, Some(ed_key(&host)), None);
    let set = build_pairing_candidates(
        &inputs,
        &target,
        &ctx(EgressKind::Session, &[]),
        &opts(DialWire::V2, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert!(set.candidates.is_empty() && set.dialers.is_empty() && set.skipped.is_empty());

    let dials = Arc::new(AtomicUsize::new(0));
    let res = dial_with_policy(
        &spied(&set, &dials),
        PathPolicyConfig::default(),
        set.candidates,
    )
    .await;
    assert!(res.is_err(), "nothing to dial");
    assert_eq!(
        dials.load(Ordering::SeqCst),
        0,
        "zero dials for a legacy roster"
    );

    // A stored route next to legacy hints: only the route is a candidate.
    let mut roster = roster;
    roster
        .set_routes(
            &peer,
            vec![OperatorEndpoint {
                hint: "direct:192.168.1.9:7000".into(),
                relay_key: None,
            }],
        )
        .expect("set");
    let inputs = session_hint_inputs(roster.get(&peer).expect("entry"), None, None);
    assert_eq!(
        inputs,
        vec![HintInput::new(
            "direct:192.168.1.9:7000",
            HintSource::Stored(RouteSource::Operator)
        )]
    );
}

#[tokio::test]
async fn session_inputs_group_sources_and_add_signed_recovery_hints() {
    let host = identity(2);
    let (mut roster, peer) = client_of(&host, &[]);
    let shared = "direct:192.168.1.20:9100";
    let signed = signed_uri(&host, &[shared, "overlay://100.101.1.2:9100"], 3);
    let statement = signed
        .verify_route_statement(host.signing_key().public_key())
        .statement()
        .cloned()
        .expect("verified");
    assert!(
        roster
            .replace_signed_routes(&peer, &statement)
            .expect("replace")
    );
    roster
        .set_routes(
            &peer,
            vec![OperatorEndpoint {
                hint: shared.into(),
                relay_key: None,
            }],
        )
        .expect("set");
    let entry = roster.get(&peer).expect("entry");
    assert_eq!(
        stored_route_inputs(entry),
        vec![
            HintInput::new(shared, HintSource::Stored(RouteSource::Operator)),
            HintInput::new(
                "overlay://100.101.1.2:9100",
                HintSource::Stored(RouteSource::Signed)
            ),
        ],
        "one input per hint, strongest source wins"
    );

    let recovery = signed_uri(&host, &[shared, "direct:10.0.0.7:9100"], 9);
    let inputs = session_hint_inputs(entry, Some(&recovery), None);
    assert_eq!(inputs.len(), 3);
    assert_eq!(
        inputs[2],
        HintInput::new("direct:10.0.0.7:9100", HintSource::Uri)
    );
    assert_eq!(inputs[0].source, HintSource::Stored(RouteSource::Operator));

    let unsigned = unsigned_uri(&host, &["direct:10.0.0.8:9100"]);
    assert_eq!(session_hint_inputs(entry, Some(&unsigned), None).len(), 2);

    let op = normalize_operator_endpoint("10.0.0.9:9100").expect("op");
    assert_eq!(
        session_hint_inputs(entry, Some(&recovery), Some(&op)),
        vec![HintInput::new("direct:10.0.0.9:9100", HintSource::Operator)],
        "an explicit operator endpoint replaces stored and recovery hints"
    );
}

#[tokio::test]
async fn builder_carries_the_route_source_into_candidate_order() {
    let hints = vec![
        HintInput::new(
            "direct:192.168.1.20:9100",
            HintSource::Stored(RouteSource::Signed),
        ),
        HintInput::new(
            "relay:ws://127.0.0.1:9/v1/relay",
            HintSource::Stored(RouteSource::Operator),
        ),
        HintInput::new("overlay://100.101.1.2:9100", HintSource::Uri),
    ];
    let target = HintTarget::pairing(Some([7; 32]));
    let set = build_pairing_candidates(
        &hints,
        &target,
        &ctx(EgressKind::Pairing(PairingCodeKind::Remote3Group), &[]),
        &opts(DialWire::V2, RelayClientAuth::None),
    )
    .await
    .expect("build");
    let sources: Vec<_> = set.candidates.iter().map(|c| c.source).collect();
    assert_eq!(
        sources,
        vec![Some(RouteSource::Signed), Some(RouteSource::Operator), None]
    );
    let mut sorted = set.candidates;
    tendril_core::policy::sort_candidates(&mut sorted);
    assert_eq!(sorted[0].addr, "relay:ws://127.0.0.1:9/v1/relay");
}

#[tokio::test]
async fn builder_dedupes_strips_prefixes_and_applies_wire_filters() {
    let hints = vec![
        HintInput::new("direct:192.168.1.20:9100", HintSource::Uri),
        HintInput::new(
            "direct:192.168.1.20:9100",
            HintSource::Stored(RouteSource::Signed),
        ),
        HintInput::new("local:/tmp/tendril.sock", HintSource::Uri),
        HintInput::new("local:/tmp/op.sock", HintSource::Operator),
        HintInput::new("ws://127.0.0.1:9/v2/relay", HintSource::Uri),
        HintInput::new("relay:ws://127.0.0.1:9/v1/relay", HintSource::Uri),
        HintInput::new("ws://127.0.0.1:9/v1/relay#abc", HintSource::Uri),
        HintInput::new("overlay://100.101.1.2:9100", HintSource::Uri),
    ];
    let target = HintTarget::pairing(Some([7; 32]));
    let set = build_pairing_candidates(
        &hints,
        &target,
        &ctx(EgressKind::Pairing(PairingCodeKind::Remote3Group), &[]),
        &opts(DialWire::V2, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert_eq!(
        addrs(&set),
        vec![
            "direct:192.168.1.20:9100",
            "local:/tmp/op.sock",
            "relay:ws://127.0.0.1:9/v1/relay",
            "overlay://100.101.1.2:9100",
        ]
    );
    let direct = set.info(0).expect("info");
    assert_eq!(direct.source, HintSource::Stored(RouteSource::Signed));
    assert_eq!(direct.dial_endpoint, "192.168.1.20:9100");
    assert_eq!(set.info(1).expect("info").dial_endpoint, "/tmp/op.sock");
    assert_eq!(
        set.info(2).expect("info").dial_endpoint,
        "ws://127.0.0.1:9/v1/relay"
    );
    assert_eq!(
        skip_of(&set, "local:/tmp/tendril.sock"),
        Some(SkipReason::IpcFromUri)
    );
    assert_eq!(
        skip_of(&set, "ws://127.0.0.1:9/v2/relay"),
        Some(SkipReason::RelayV2NotAuthorized),
        "/v2/relay is never dialed during pairing"
    );
    assert_eq!(
        skip_of(&set, "ws://127.0.0.1:9/v1/relay#abc"),
        Some(SkipReason::Invalid),
        "a hint carrying a fragment never supplies the target key"
    );
    assert_eq!(set.original_hint(3), Some("overlay://100.101.1.2:9100"));

    // Lan2Group: remote rungs are skipped before any dial.
    let set = build_pairing_candidates(
        &hints,
        &target,
        &ctx(EgressKind::Pairing(PairingCodeKind::Lan2Group), &[]),
        &opts(DialWire::V2, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert_eq!(
        addrs(&set),
        vec!["direct:192.168.1.20:9100", "local:/tmp/op.sock"]
    );
    assert_eq!(
        skip_of(&set, "overlay://100.101.1.2:9100"),
        Some(SkipReason::LanCodeRemoteHint)
    );

    // A relay hint without a target key cannot be dialed.
    let set = build_pairing_candidates(
        &[HintInput::new("ws://127.0.0.1:9/v1/relay", HintSource::Uri)],
        &HintTarget::pairing(None),
        &ctx(EgressKind::Session, &[]),
        &opts(DialWire::V1, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert!(set.candidates.is_empty());
    assert_eq!(
        skip_of(&set, "ws://127.0.0.1:9/v1/relay"),
        Some(SkipReason::Invalid)
    );
}

#[tokio::test]
async fn candidates_dial_their_checked_target_and_report_the_original_hint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });
    let hint = format!("direct:{addr}");
    let set = build_pairing_candidates(
        &[
            HintInput::new("direct:240.0.0.1:80", HintSource::Uri),
            HintInput::new(&hint, HintSource::Uri),
        ],
        &HintTarget::pairing(None),
        &ctx(EgressKind::Pairing(PairingCodeKind::Lan2Group), &[]),
        &opts(DialWire::V1, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert_eq!(
        skip_of(&set, "direct:240.0.0.1:80"),
        Some(SkipReason::BlockedAddress)
    );
    let (winner, stream) = dial_with_policy(
        &set.dialers,
        PathPolicyConfig::default(),
        set.candidates.clone(),
    )
    .await
    .expect("dial");
    assert_eq!(winner.addr, hint);
    assert_eq!(set.original_hint(winner.id), Some(hint.as_str()));
    assert_eq!(stream.provider_id(), ProviderId::Direct);
}

#[cfg(not(feature = "p2p-iroh"))]
#[tokio::test]
async fn p2p_only_candidates_fail_without_the_feature() {
    let err = build_pairing_candidates(
        &[HintInput::new("iroh://abc", HintSource::Uri)],
        &HintTarget::pairing(None),
        &ctx(EgressKind::Session, &[]),
        &opts(DialWire::V1, RelayClientAuth::None),
    )
    .await
    .expect_err("feature disabled");
    assert!(err.to_string().contains("p2p-iroh feature is not enabled"));
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn iroh_hints_use_the_lookup_free_dialer_and_operator_routes_keep_theirs() {
    use tendril_runtime::providers::P2pRelayMode;

    let node = iroh::SecretKey::from_bytes(&[9; 32]).public();
    let uri_hint = format!("iroh://{node}?relay=https://relay.attacker.example/");
    let op_hint = format!("iroh://{node}?addr=192.168.1.4:4000");
    let dialers = HintDialers::new(HintDialerConfig {
        p2p_relay_mode: P2pRelayMode::Custom("http://127.0.0.1:3340/".into()),
        p2p_port_mapping: false,
        ..HintDialerConfig::default()
    });
    let ctx = dialers.egress_context(EgressKind::Session, Vec::new());
    let opts = MultiDialOptions::new(Arc::new(dialers), DialWire::V2);
    let set = build_pairing_candidates(
        &[
            HintInput::new(&uri_hint, HintSource::Uri),
            HintInput::new(&op_hint, HintSource::Stored(RouteSource::Operator)),
        ],
        &HintTarget::session("peer", None, None),
        &ctx,
        &opts,
    )
    .await
    .expect("build");
    assert_eq!(set.candidates.len(), 2);
    let uri_info = set.info(0).expect("info");
    assert!(
        uri_info.dial_endpoint.contains("127.0.0.1:3340")
            && !uri_info.dial_endpoint.contains("attacker"),
        "{}",
        uri_info.dial_endpoint
    );
    assert_eq!(
        skip_of(&set, "https://relay.attacker.example/"),
        Some(SkipReason::IrohRelayNotConfigured)
    );
    assert_eq!(set.info(1).expect("info").dial_endpoint, op_hint);

    let hint_dialer = opts.dialers.p2p_hint_dialer().await.expect("bind");
    assert!(hint_dialer.is_hint_dialer());
    assert!(!hint_dialer.uses_address_lookup());
}

/// Stub `/v1/relay` demanding dial authentication; records whether each dial carried auth.
async fn stub_auth_relay() -> (u16, Arc<Mutex<Vec<bool>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_c = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = Arc::clone(&seen_c);
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let challenge = RelayServerMsg::Challenge {
                    nonce: b64url_encode(&[3; 32]),
                    host: "127.0.0.1".into(),
                    max_frame: MAX_RELAY_FRAME_LEN,
                    auth_required: Some(vec!["dial".into()]),
                    fast_open: None,
                    standby: None,
                };
                let text = serde_json::to_string(&challenge).expect("json");
                if ws.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
                while let Some(Ok(msg)) = ws.next().await {
                    let Message::Text(text) = msg else { continue };
                    let Ok(RelayClientMsg::Dial { conn_id, auth, .. }) =
                        serde_json::from_str::<RelayClientMsg>(&text)
                    else {
                        return;
                    };
                    seen.lock().expect("seen").push(auth.is_some());
                    let reply = if auth.is_some() {
                        RelayServerMsg::Ready { conn_id }
                    } else {
                        RelayServerMsg::Error {
                            code: "auth_required".into(),
                        }
                    };
                    let text = serde_json::to_string(&reply).expect("json");
                    let _ = ws.send(Message::Text(text.into())).await;
                    let _ = ws.next().await;
                    return;
                }
            });
        }
    });
    (port, seen)
}

async fn dial_relay(set: &CandidateSet) -> Result<Box<dyn PathStream>, RuntimeError> {
    let cand = set.candidates.first().expect("relay candidate");
    set.dialer_for(ProviderId::Relay)
        .expect("relay dialer")
        .dial(&cand.addr)
        .await
}

#[tokio::test]
async fn relay_credentials_follow_the_origin_allow_list() {
    let (port, seen) = stub_auth_relay().await;
    let url = format!("ws://127.0.0.1:{port}/v1/relay");
    let origin = format!("ws://127.0.0.1:{port}");
    let target = HintTarget::pairing(Some([7; 32]));
    let kind = EgressKind::Pairing(PairingCodeKind::Remote3Group);
    let uri_input = [HintInput::new(&url, HintSource::Uri)];

    // A URI origin outside relay_auth_origins: no admission material, fast typed failure.
    let set = build_pairing_candidates(
        &uri_input,
        &target,
        &ctx(kind, &[]),
        &opts(DialWire::V1, hmac_auth()),
    )
    .await
    .expect("build");
    assert!(!set.info(0).expect("info").relay_credentials);
    let err = dial_relay(&set).await.err().expect("refused");
    assert!(err.to_string().contains("relay_auth_unconfigured"), "{err}");
    assert!(
        seen.lock().expect("seen").is_empty(),
        "no dial frame was sent"
    );

    // Host equality is not origin equality: another port does not match.
    let other = format!("ws://127.0.0.1:{}", port.wrapping_add(1));
    let set = build_pairing_candidates(
        &uri_input,
        &target,
        &ctx(kind, &[other.as_str()]),
        &opts(DialWire::V1, hmac_auth()),
    )
    .await
    .expect("build");
    assert!(!set.info(0).expect("info").relay_credentials);

    // Byte-equal origin: the dial carries admission material.
    let set = build_pairing_candidates(
        &uri_input,
        &target,
        &ctx(kind, &[origin.as_str()]),
        &opts(DialWire::V1, hmac_auth()),
    )
    .await
    .expect("build");
    assert!(set.info(0).expect("info").relay_credentials);
    dial_relay(&set).await.expect("authorized dial");

    // The explicit operator endpoint of this call also receives them.
    let op =
        normalize_operator_endpoint(&format!("{url}#{}", b64url_encode(&ed_key(&identity(4)))))
            .expect("op");
    let set = build_pairing_candidates(
        &[HintInput::new(&op.hint, HintSource::Operator)],
        &HintTarget::pairing(op.relay_key),
        &ctx(kind, &[]),
        &opts(DialWire::V1, hmac_auth()),
    )
    .await
    .expect("build");
    assert!(set.info(0).expect("info").relay_credentials);
    dial_relay(&set).await.expect("operator dial");

    // A stored signed route is learned, not configured.
    let set = build_pairing_candidates(
        &[HintInput::new(
            &url,
            HintSource::Stored(RouteSource::Signed),
        )],
        &HintTarget::session("peer", Some([7; 32]), None),
        &ctx(EgressKind::Session, &[]),
        &opts(DialWire::V1, hmac_auth()),
    )
    .await
    .expect("build");
    assert!(!set.info(0).expect("info").relay_credentials);
    assert_eq!(*seen.lock().expect("seen"), vec![true, true]);
}

#[tokio::test]
async fn relay_adapter_rejects_fragments() {
    let err = RelayHintDialer::new([7; 32])
        .dial("ws://127.0.0.1:9/v1/relay#AAAA")
        .await
        .err()
        .expect("rejected");
    assert!(
        err.to_string()
            .contains("invalid: relay hint must not carry a fragment"),
        "{err}"
    );
}

const LEGACY_V2: &str = "ws://127.0.0.9:9/v2/relay";

fn v2_fixture(host: &EndpointIdentity) -> (Roster, String) {
    let (mut roster, peer) = client_of(host, &[LEGACY_V2]);
    roster
        .set_peer_v2_secrets(&peer, V2PeerSecrets::new([1; 32], [2; 32]))
        .expect("secrets");
    (roster, peer)
}

async fn v2_build(
    roster: &Roster,
    gate_peer: &str,
    target_peer: &str,
    inputs: &[HintInput],
    wire: DialWire,
) -> (CandidateSet, usize) {
    let target = HintTarget::session(
        target_peer,
        None,
        Some(RelayV2Gate::authorize(roster, gate_peer)),
    );
    let set = build_pairing_candidates(
        inputs,
        &target,
        &ctx(EgressKind::Session, &[]),
        &opts(wire, RelayClientAuth::None),
    )
    .await
    .expect("build");
    let releases = target.relay_v2_gate().expect("gate").releases();
    (set, releases)
}

#[tokio::test]
async fn stored_relay_v2_routes_pass_the_gate_only_when_authorized() {
    const OP: &str = "ws://127.0.0.1:9/v2/relay";
    const SIGNED: &str = "ws://127.0.0.2:9/v2/relay";
    let host = identity(5);
    let (mut roster, peer) = v2_fixture(&host);
    roster
        .set_routes(
            &peer,
            vec![OperatorEndpoint {
                hint: OP.into(),
                relay_key: None,
            }],
        )
        .expect("operator v2 route");
    let statement = signed_uri(&host, &[SIGNED], 4)
        .verify_route_statement(host.signing_key().public_key())
        .statement()
        .cloned()
        .expect("verified");
    assert!(
        roster
            .replace_signed_routes(&peer, &statement)
            .expect("signed")
    );

    // Operator and signed routes: released and dialable.
    let inputs = session_hint_inputs(roster.get(&peer).expect("entry"), None, None);
    let (set, releases) = v2_build(&roster, &peer, &peer, &inputs, DialWire::V2).await;
    assert_eq!(addrs(&set), vec![OP, SIGNED]);
    assert_eq!(releases, 0, "the secret is released only inside a dial");

    // Wire v1 driver: dropped before any release.
    let (set, releases) = v2_build(&roster, &peer, &peer, &inputs, DialWire::V1).await;
    assert!(set.candidates.is_empty());
    assert_eq!(skip_of(&set, OP), Some(SkipReason::WireV1NoRelayV2));
    assert_eq!(releases, 0);

    // A hint not in routes, the legacy hint, a committed source: never released.
    let stray = [
        HintInput::new("ws://127.0.0.3:9/v2/relay", HintSource::Uri),
        HintInput::new(LEGACY_V2, HintSource::Uri),
        HintInput::new(
            "ws://127.0.0.4:9/v2/relay",
            HintSource::Stored(RouteSource::Committed),
        ),
    ];
    let (set, releases) = v2_build(&roster, &peer, &peer, &stray, DialWire::V2).await;
    assert!(set.candidates.is_empty());
    assert!(
        set.skipped
            .iter()
            .all(|s| s.reason == SkipReason::RelayV2NotAuthorized)
    );
    assert_eq!(releases, 0);
    let entry = roster.get(&peer).expect("entry");
    let legacy = session_hint_inputs(entry, None, None);
    assert!(
        !legacy.iter().any(|i| entry.relay_hints.contains(&i.hint)),
        "the legacy v2 relay hint is not an input"
    );

    // A committed /v2/relay record forced into the roster file is never released.
    let mut value = serde_json::to_value(&roster).expect("json");
    value["entries"][&peer]["routes"] =
        serde_json::json!([{ "hint": "ws://127.0.0.4:9/v2/relay", "source": "committed" }]);
    let forced: Roster = serde_json::from_value(value).expect("forced fixture");
    let inputs = session_hint_inputs(forced.get(&peer).expect("entry"), None, None);
    assert_eq!(inputs.len(), 1);
    let (set, releases) = v2_build(&forced, &peer, &peer, &inputs, DialWire::V2).await;
    assert!(set.candidates.is_empty());
    assert_eq!(releases, 0);

    // Another entry's route: a gate for a different peer admits nothing.
    let other = identity(6);
    let (mut other_roster, other_peer) = v2_fixture(&other);
    other_roster
        .set_routes(
            &other_peer,
            vec![OperatorEndpoint {
                hint: OP.into(),
                relay_key: None,
            }],
        )
        .expect("other route");
    let inputs = [HintInput::new(
        OP,
        HintSource::Stored(RouteSource::Operator),
    )];
    let (set, releases) = v2_build(&other_roster, &other_peer, &peer, &inputs, DialWire::V2).await;
    assert!(set.candidates.is_empty());
    assert_eq!(releases, 0);
    let (set, releases) = v2_build(&roster, &peer, &peer, &inputs, DialWire::V2).await;
    assert_eq!(addrs(&set), vec![OP]);
    assert_eq!(releases, 0);

    // A peer without v2 secrets: nothing released even for its operator input.
    let (plain, plain_peer) = client_of(&identity(7), &[]);
    let op_inputs = [HintInput::new(OP, HintSource::Operator)];
    let (set, releases) =
        v2_build(&plain, &plain_peer, &plain_peer, &op_inputs, DialWire::V2).await;
    assert!(set.candidates.is_empty());
    assert_eq!(releases, 0);
    // The same explicit operator input to a v2 peer keeps today's behaviour.
    let (set, releases) = v2_build(&roster, &peer, &peer, &op_inputs, DialWire::V2).await;
    assert_eq!(addrs(&set), vec![OP]);
    assert_eq!(releases, 0);

    // A revoked entry releases nothing.
    roster.revoke_peer(&peer).expect("revoke");
    let inputs = [HintInput::new(
        OP,
        HintSource::Stored(RouteSource::Operator),
    )];
    let (set, releases) = v2_build(&roster, &peer, &peer, &inputs, DialWire::V2).await;
    assert!(set.candidates.is_empty());
    assert_eq!(releases, 0);
}

#[tokio::test]
async fn relay_v2_is_classified_on_the_normalized_path() {
    for hint in [
        "ws://127.0.0.1:9/x/../v2/relay",
        "wss://relay.example/v2/./relay",
        "wss://relay.example/%2e%2e/v2/relay",
        "relay:wss://relay.example/a/b/../../v2/relay?x=1",
    ] {
        assert!(is_v2_relay_hint(hint), "{hint}");
    }
    assert!(!is_v2_relay_hint("wss://relay.example/v2/relay/x"));
    assert!(!is_v2_relay_hint("wss://relay.example/v1/relay"));

    let dotted = "ws://127.0.0.1:9/x/../v2/relay";
    let target = HintTarget::pairing(Some([7; 32]));
    let set = build_pairing_candidates(
        &[HintInput::new(dotted, HintSource::Uri)],
        &target,
        &ctx(EgressKind::Pairing(PairingCodeKind::Remote3Group), &[]),
        &opts(DialWire::V2, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert!(set.candidates.is_empty(), "never dialed as /v1/relay");
    assert_eq!(
        skip_of(&set, dotted),
        Some(SkipReason::RelayV2NotAuthorized)
    );

    let set = build_pairing_candidates(
        &[HintInput::new(
            dotted,
            HintSource::Stored(RouteSource::Signed),
        )],
        &HintTarget::session("peer", Some([7; 32]), None),
        &ctx(EgressKind::Session, &[]),
        &opts(DialWire::V1, RelayClientAuth::None),
    )
    .await
    .expect("build");
    assert!(set.candidates.is_empty());
    assert_eq!(skip_of(&set, dotted), Some(SkipReason::WireV1NoRelayV2));
}

/// Fixed answers per host for the egress policy.
struct MapResolver(Vec<(&'static str, &'static str)>);

#[async_trait]
impl HostResolver for MapResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        self.0
            .iter()
            .filter(|(h, _)| *h == host)
            .map(|(_, ip)| Ok(SocketAddr::new(ip.parse().expect("ip"), port)))
            .collect()
    }
}

/// Stub `/v2/relay`: sends a challenge, optionally demanding dial auth, records whether each
/// `dial` frame carried auth, and rejects it.
async fn stub_v2_relay(demand_auth: bool) -> (u16, Arc<Mutex<Vec<bool>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_c = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = Arc::clone(&seen_c);
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let challenge = RelayV2ServerMsg::Challenge {
                    nonce: b64url_encode(&[3; 32]),
                    host: "127.0.0.1".into(),
                    epoch: 1,
                    max_frame: MAX_RELAY_FRAME_LEN,
                    auth_required: demand_auth.then(|| vec!["dial".into()]),
                    fast_open: None,
                    standby: None,
                };
                let text = serde_json::to_string(&challenge).expect("json");
                if ws.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
                while let Some(Ok(msg)) = ws.next().await {
                    let Message::Text(text) = msg else { continue };
                    let Ok(RelayV2ClientMsg::Dial { auth, .. }) =
                        serde_json::from_str::<RelayV2ClientMsg>(&text)
                    else {
                        return;
                    };
                    seen.lock().expect("seen").push(auth.is_some());
                    let reply = RelayV2ServerMsg::Error {
                        code: "no_such_mailbox".into(),
                    };
                    let text = serde_json::to_string(&reply).expect("json");
                    let _ = ws.send(Message::Text(text.into())).await;
                    return;
                }
            });
        }
    });
    (port, seen)
}

/// Builds the Wire v2 session candidates of `hint` (a stored operator route of `peer`) and
/// dials the first one; returns the error and the gate's release count.
async fn v2_dial(
    roster: &Roster,
    peer: &str,
    hint: &str,
    origins: &[&str],
    auth: RelayClientAuth,
) -> (RuntimeError, usize) {
    let target = HintTarget::session(peer, None, Some(RelayV2Gate::authorize(roster, peer)));
    let resolver = MapResolver(vec![("v2-blocked.example", "240.0.0.1")]);
    let ctx = EgressContext::new(EgressKind::Session)
        .with_resolver(Arc::new(resolver))
        .with_relay_auth_origins(owned(origins));
    let set = build_pairing_candidates(
        &[HintInput::new(
            hint,
            HintSource::Stored(RouteSource::Operator),
        )],
        &target,
        &ctx,
        &opts(DialWire::V2, auth),
    )
    .await
    .expect("build");
    assert_eq!(addrs(&set), vec![hint], "the gate admits the route");
    assert_eq!(
        target.relay_v2_gate().expect("gate").releases(),
        0,
        "nothing released while building"
    );
    let err = dial_relay(&set).await.err().expect("dial fails");
    (err, target.relay_v2_gate().expect("gate").releases())
}

#[tokio::test]
async fn relay_v2_secret_is_released_only_after_the_checks_pass() {
    const BLOCKED: &str = "wss://v2-blocked.example/v2/relay";
    let (demanding, demanding_seen) = stub_v2_relay(true).await;
    let (open, open_seen) = stub_v2_relay(false).await;
    let demanding_url = format!("ws://127.0.0.1:{demanding}/v2/relay");
    let open_url = format!("ws://127.0.0.1:{open}/v2/relay");
    let host = identity(12);
    let (mut roster, peer) = v2_fixture(&host);
    roster
        .set_routes(
            &peer,
            [BLOCKED, demanding_url.as_str(), open_url.as_str()]
                .iter()
                .map(|h| OperatorEndpoint {
                    hint: (*h).to_owned(),
                    relay_key: None,
                })
                .collect(),
        )
        .expect("operator v2 routes");

    // A stored route whose name resolves into the blocked set: refused at the address check,
    // before the secret is released.
    let (err, releases) = v2_dial(&roster, &peer, BLOCKED, &[], RelayClientAuth::None).await;
    assert_eq!(
        err.skip_reason(),
        Some(SkipReason::BlockedAddress),
        "{err:?}"
    );
    assert_eq!(releases, 0);

    // A relay demanding dial auth while the origin gate withholds credentials: fast typed
    // failure, no dial frame, no release.
    let (err, releases) = v2_dial(&roster, &peer, &demanding_url, &[], hmac_auth()).await;
    assert!(err.to_string().contains("relay_auth_unconfigured"), "{err}");
    assert!(
        demanding_seen.lock().expect("seen").is_empty(),
        "no dial frame"
    );
    assert_eq!(releases, 0);

    // Allowlisted origin: credentials attached, dial sent, one release.
    let origin = format!("ws://127.0.0.1:{demanding}");
    let (_, releases) = v2_dial(
        &roster,
        &peer,
        &demanding_url,
        &[origin.as_str()],
        hmac_auth(),
    )
    .await;
    assert_eq!(*demanding_seen.lock().expect("seen"), vec![true]);
    assert_eq!(releases, 1);

    // A relay that demands nothing: dial sent without credentials, one release.
    let (_, releases) = v2_dial(&roster, &peer, &open_url, &[], hmac_auth()).await;
    assert_eq!(*open_seen.lock().expect("seen"), vec![false]);
    assert_eq!(releases, 1);
}

#[test]
fn route_setter_rejects_malformed_nested_urls_atomically() {
    let host = identity(13);
    let (mut roster, peer) = client_of(&host, &[]);
    set_peer_routes(&mut roster, &peer, &owned(&["10.0.0.5:9100"])).expect("set");
    let before = peer_routes(&roster, &peer, None::<()>).expect("routes");
    for bad in [
        "iroh://abc123?relay=https://999.0.0.1/",
        "iroh://abc123?addr=10.0.0.1:1&relay=https://1.2.3.4.5/",
        "broker+wss://999.0.0.1/b",
    ] {
        let err = set_peer_routes(&mut roster, &peer, &owned(&["10.0.0.6:1", bad])).expect_err(bad);
        assert!(err.to_string().contains("invalid URL"), "{bad}: {err}");
        assert_eq!(
            peer_routes(&roster, &peer, None::<()>).expect("routes"),
            before,
            "nothing written for {bad}"
        );
    }
    set_peer_routes(
        &mut roster,
        &peer,
        &owned(&["iroh://abc123?relay=https://relay.example/"]),
    )
    .expect("a well-formed nested relay is accepted");
}

/// `set_peer_routes_in` and `clear_peer_routes_in` run one transaction on the handle: the store
/// and the in-memory copy both change, and rejected input writes nothing.
#[test]
fn route_setters_on_a_handle_persist_and_reject_atomically() {
    let host = identity(14);
    let (roster, peer) = client_of(&host, &[]);
    let dir = tempfile::tempdir().expect("dir");
    let state = Arc::new(StateStore::open_or_create(dir.path()).expect("store"));
    state.save_roster(&roster).expect("save");
    let stored = RosterAccess::from_store(Arc::clone(&state)).expect("handle");
    let memory = RosterAccess::memory(roster);
    let want = owned(&["direct:10.0.0.5:9100", "overlay://100.64.0.2:9100"]);

    for access in [&stored, &memory] {
        let written = set_peer_routes_in(
            access,
            &peer,
            &owned(&["10.0.0.5:9100", "overlay://100.64.0.2:9100"]),
        )
        .expect("set");
        assert_eq!(
            written.iter().map(|r| r.hint.clone()).collect::<Vec<_>>(),
            want
        );
        let in_memory = access.roster().lock().expect("roster").clone();
        assert_eq!(routes_of(&in_memory, &peer, RouteSource::Operator), want);
        assert_eq!(
            routes_of(&access.load().expect("load"), &peer, RouteSource::Operator),
            want
        );

        for bad in [
            owned(&["10.0.0.6:1", "broker+wss://999.0.0.1/b"]),
            owned(&["wss://u:pw@relay.example/v1/relay"]),
        ] {
            assert!(set_peer_routes_in(access, &peer, &bad).is_err(), "{bad:?}");
            assert_eq!(
                routes_of(&access.load().expect("load"), &peer, RouteSource::Operator),
                want,
                "nothing written for {bad:?}"
            );
        }
        assert!(set_peer_routes_in(access, "no-such-peer", &owned(&["10.0.0.7:1"])).is_err());

        clear_peer_routes_in(access, &peer, Some(RouteSource::Signed)).expect("clear signed");
        assert_eq!(
            routes_of(&access.load().expect("load"), &peer, RouteSource::Operator),
            want,
            "clearing another source keeps operator routes"
        );
        clear_peer_routes_in(access, &peer, None).expect("clear all");
        let cleared = access.load().expect("load");
        assert!(routes_of(&cleared, &peer, RouteSource::Operator).is_empty());
        assert!(
            routes_of(
                &access.roster().lock().expect("roster"),
                &peer,
                RouteSource::Operator
            )
            .is_empty()
        );
    }
    assert!(
        routes_of(
            &state.load_roster().expect("disk"),
            &peer,
            RouteSource::Operator
        )
        .is_empty(),
        "the store saw the clear"
    );
}

#[test]
fn operator_endpoints_normalize_to_persistable_hints() {
    let key = ed_key(&identity(8));
    let key_b64 = b64url_encode(&key);
    let cases: &[(&str, &str)] = &[
        ("/run/tendril.sock", "local:/run/tendril.sock"),
        ("unix:///run/tendril.sock", "unix:///run/tendril.sock"),
        ("local:/run/tendril.sock", "local:/run/tendril.sock"),
        ("192.168.1.4:9000", "direct:192.168.1.4:9000"),
        ("[fd00::4]:9000", "direct:[fd00::4]:9000"),
        ("host.example:9000", "direct:host.example:9000"),
        ("direct:10.0.0.1:1", "direct:10.0.0.1:1"),
        ("overlay://100.64.0.1:1", "overlay://100.64.0.1:1"),
        (
            "wss://relay.example/v2/relay#bWFpbGJveA",
            "wss://relay.example/v2/relay",
        ),
    ];
    for (raw, want) in cases {
        let ep = normalize_operator_endpoint(raw).expect(raw);
        assert_eq!(ep.hint, *want, "{raw}");
        assert_eq!(ep.relay_key, None, "{raw}");
    }
    let ep = normalize_operator_endpoint(&format!("wss://relay.example/v1/relay#{key_b64}"))
        .expect("relay key");
    assert_eq!(ep.hint, "wss://relay.example/v1/relay");
    assert_eq!(ep.relay_key, Some(key));

    let not_a_point = (0..=u8::MAX)
        .map(|b| [b; 32])
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
        .expect("an invalid point");
    for bad in [
        "direct:10.0.0.1:1#x".to_owned(),
        "/run/tendril.sock#x".to_owned(),
        "wss://relay.example/v1/relay#short".to_owned(),
        format!(
            "wss://relay.example/v1/relay#{}",
            b64url_encode(&not_a_point)
        ),
        "not a hint".to_owned(),
        "relative/path".to_owned(),
    ] {
        let err = normalize_operator_endpoint(&bad).expect_err(&bad);
        assert!(
            matches!(err, RuntimeError::Core(CoreError::InvalidPairingUri(_))),
            "{bad}: {err}"
        );
    }
    assert!(
        normalize_operator_endpoint("direct:10.0.0.1:1#x")
            .expect_err("fragment")
            .to_string()
            .contains("fragment not allowed")
    );
}

#[test]
fn route_setter_is_atomic_and_leaves_signed_routes() {
    let host = identity(9);
    let other_key = ed_key(&identity(10));
    let (mut roster, peer) = client_of(&host, &[]);
    let statement = signed_uri(&host, &["direct:192.168.1.20:9100"], 2)
        .verify_route_statement(host.signing_key().public_key())
        .statement()
        .cloned()
        .expect("verified");
    assert!(
        roster
            .replace_signed_routes(&peer, &statement)
            .expect("signed")
    );

    let raw = owned(&[
        "/run/tendril.sock",
        "10.0.0.5:9100",
        &format!(
            "ws://127.0.0.1:9/v1/relay#{}",
            b64url_encode(&ed_key(&host))
        ),
    ]);
    let routes = set_peer_routes(&mut roster, &peer, &raw).expect("set");
    let operator: Vec<&str> = routes
        .iter()
        .filter(|r| r.source == RouteSource::Operator)
        .map(|r| r.hint.as_str())
        .collect();
    assert_eq!(
        operator,
        vec![
            "local:/run/tendril.sock",
            "direct:10.0.0.5:9100",
            "ws://127.0.0.1:9/v1/relay"
        ]
    );
    let before = peer_routes(&roster, &peer, None::<()>).expect("routes");
    assert_eq!(
        peer_routes(&roster, &peer, Some("stale_seq"))
            .expect("routes")
            .last_route_set,
        Some("stale_seq"),
        "the caller's last route set record is passed through"
    );
    assert!(before.routes.contains(&StoredRoute {
        hint: "direct:192.168.1.20:9100".into(),
        source: RouteSource::Signed,
    }));

    let rejects: Vec<Vec<String>> = vec![
        owned(&["10.0.0.6:1", "direct:10.0.0.7:1#frag"]),
        owned(&["10.0.0.6:1", "direct:0.0.0.1:9"]),
        owned(&["10.0.0.6:1", "overlay://240.0.0.1:9"]),
        owned(&["10.0.0.6:1", "wss://169.254.169.254/v1/relay"]),
        vec![
            "10.0.0.6:1".to_owned(),
            format!("ws://127.0.0.1:9/v1/relay#{}", b64url_encode(&other_key)),
        ],
        (1..=7).map(|i| format!("10.0.0.{i}:1")).collect(),
    ];
    for bad in &rejects {
        assert!(set_peer_routes(&mut roster, &peer, bad).is_err(), "{bad:?}");
        assert_eq!(
            peer_routes(&roster, &peer, None::<()>).expect("routes"),
            before,
            "nothing written for {bad:?}"
        );
    }
    let err = set_peer_routes(
        &mut roster,
        &peer,
        &[format!(
            "ws://127.0.0.1:9/v1/relay#{}",
            b64url_encode(&other_key)
        )],
    )
    .expect_err("wrong key");
    assert!(
        err.to_string().contains("relay key does not match"),
        "{err}"
    );

    let routes = set_peer_routes(&mut roster, &peer, &[]).expect("clear operator");
    assert_eq!(
        routes,
        vec![StoredRoute {
            hint: "direct:192.168.1.20:9100".into(),
            source: RouteSource::Signed,
        }]
    );
    clear_peer_routes(&mut roster, &peer, None).expect("clear");
    let after = peer_routes(&roster, &peer, None::<()>).expect("routes");
    assert!(after.routes.is_empty());
    assert_eq!(after.route_meta.map(|m| m.seq), Some(2), "route_meta kept");
    assert!(matches!(
        set_peer_routes(&mut roster, "missing", &[]),
        Err(RuntimeError::Core(CoreError::PeerNotFound(_)))
    ));
}

#[test]
fn route_setter_writes_through_the_state_store() {
    let dir = tempfile::tempdir().expect("dir");
    let state = StateStore::open_or_create(dir.path()).expect("store");
    let host = identity(11);
    let (roster, peer) = client_of(&host, &[]);
    state.save_roster(&roster).expect("save");
    state
        .update_roster(|r| set_peer_routes(r, &peer, &owned(&["10.0.0.5:9100"])))
        .expect("set");
    assert_eq!(
        routes_of(
            &state.load_roster().expect("load"),
            &peer,
            RouteSource::Operator
        ),
        vec!["direct:10.0.0.5:9100"]
    );
    assert!(
        state
            .update_roster(|r| set_peer_routes(
                r,
                &peer,
                &owned(&["10.0.0.5:9100", "direct:0.0.0.0:1"])
            ))
            .is_err()
    );
    assert_eq!(
        routes_of(
            &state.load_roster().expect("load"),
            &peer,
            RouteSource::Operator
        ),
        vec!["direct:10.0.0.5:9100"]
    );
}

#[test]
fn offline_signed_uri_application_matches_keys_and_sequence() {
    let host = identity(12);
    let (mut roster, peer) = client_of(&host, &[]);
    let all_signed = RouteApplyOpts::default();

    let fresh = signed_uri(
        &host,
        &["direct:192.168.1.20:9100", "overlay://100.64.0.9:1"],
        5,
    );
    let res = apply_signed_route_uri(&mut roster, &fresh, all_signed).expect("apply");
    assert!(res.applied);
    assert_eq!(res.peer_id, peer);
    assert_eq!(
        res.route_meta,
        Some(RouteMeta {
            seq: 5,
            issued_at: None,
            origin: RouteOrigin::Uri
        })
    );
    assert_eq!(res.routes.len(), 2);

    // Stale: unchanged without approval, replaced with it, sequence never lowered.
    let stale = signed_uri(&host, &["direct:192.168.1.30:9100"], 4);
    let res = apply_signed_route_uri(&mut roster, &stale, all_signed).expect("stale");
    assert!(!res.applied);
    assert_eq!(res.reason, Some("stale_route_seq"));
    assert_eq!(res.routes.len(), 2);
    let approved = RouteApplyOpts {
        replace_routes: true,
        ..RouteApplyOpts::default()
    };
    let res = apply_signed_route_uri(&mut roster, &stale, approved).expect("approved");
    assert!(res.applied);
    assert_eq!(
        routes_of(&roster, &peer, RouteSource::Signed),
        vec!["direct:192.168.1.30:9100"]
    );
    assert_eq!(
        res.route_meta.map(|m| (m.seq, m.origin)),
        Some((5, RouteOrigin::Approved))
    );

    // Policy other than allSigned changes nothing without approval.
    let newer = signed_uri(&host, &["direct:192.168.1.40:9100"], 9);
    let res = apply_signed_route_uri(
        &mut roster,
        &newer,
        RouteApplyOpts {
            policy: RoutePolicy::CommittedOnly,
            replace_routes: false,
        },
    )
    .expect("policy");
    assert!(!res.applied);
    assert_eq!(res.reason, Some("route_policy"));

    // Unknown keys, unsigned and tampered URIs.
    let stranger = signed_uri(&identity(13), &["direct:192.168.1.50:9100"], 9);
    let err = apply_signed_route_uri(&mut roster, &stranger, all_signed).expect_err("unknown");
    assert!(
        matches!(&err, RuntimeError::Core(CoreError::PeerNotFound(m)) if m.contains("recovery URI")),
        "{err}"
    );
    // Signed by the pinned host but naming another static key `k`: no entry matches.
    let mut wrong_k = PairingUri::new(
        "Studio",
        "TND-ABCD-EFGH-JKLM",
        *identity(15).static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        owned(&["direct:192.168.1.55:9100"]),
        Some(host.host_id().to_owned()),
        Some(0),
    );
    wrong_k.relay_pub = None;
    let prefix = format!("{}&rq=30", wrong_k.try_encode().expect("encode"));
    let sig = sign_route_statement(&host, &prefix);
    let wrong_k =
        PairingUri::parse(&format!("{prefix}&rs={}", b64url_encode(&sig))).expect("parse");
    let err = apply_signed_route_uri(&mut roster, &wrong_k, all_signed).expect_err("wrong k");
    assert!(
        matches!(&err, RuntimeError::Core(CoreError::PeerNotFound(_))),
        "{err}"
    );
    let err = apply_signed_route_uri(
        &mut roster,
        &unsigned_uri(&host, &["direct:192.168.1.60:9100"]),
        all_signed,
    )
    .expect_err("unsigned");
    assert!(err.to_string().contains("not host-signed"), "{err}");
    let other = identity(14);
    let mut forged = PairingUri::new(
        "Studio",
        "TND-ABCD-EFGH-JKLM",
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        owned(&["direct:192.168.1.70:9100"]),
        Some(host.host_id().to_owned()),
        Some(0),
    );
    forged.relay_pub = None;
    let prefix = format!("{}&rq=20", forged.try_encode().expect("encode"));
    let sig = sign_route_statement(&other, &prefix);
    let forged = PairingUri::parse(&format!("{prefix}&rs={}", b64url_encode(&sig))).expect("parse");
    let err = apply_signed_route_uri(&mut roster, &forged, all_signed).expect_err("forged");
    assert!(err.to_string().contains("does not verify"), "{err}");
    assert_eq!(
        routes_of(&roster, &peer, RouteSource::Signed),
        vec!["direct:192.168.1.30:9100"],
        "rejected URIs change nothing"
    );
}

#[test]
fn blocked_literals_include_nested_iroh_and_relay_hosts() {
    use tendril_runtime::providers::hints::hint_has_blocked_literal;
    for hint in [
        "direct:0.0.0.1:9",
        "wt://0.0.0.1:4433",
        "overlay://240.0.0.1:9",
        "wss://240.0.0.1/v1/relay",
        "broker+wss://240.0.0.2/x",
        "iroh://abc?addr=240.0.0.9:1",
        "iroh://abc?relay=https://0.0.0.7/",
    ] {
        assert!(hint_has_blocked_literal(hint), "{hint}");
    }
    for hint in [
        "direct:192.168.1.1:9",
        "wt://192.168.1.1:4433?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "wss://relay.example/v1/relay",
        "local:/run/x",
        "iroh://abc?addr=10.0.0.1:1",
    ] {
        assert!(!hint_has_blocked_literal(hint), "{hint}");
    }
    let _: IpAddr = "127.0.0.1".parse().expect("ip");
}

#[cfg(not(feature = "webtransport"))]
#[tokio::test]
async fn sole_wt_candidate_errors_when_webtransport_feature_is_disabled() {
    let opts = MultiDialOptions::new(
        Arc::new(HintDialers::new(HintDialerConfig::default())),
        DialWire::V1,
    );
    let err = build_pairing_candidates(
        &[HintInput::new(
            "wt://127.0.0.1:4433?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            HintSource::Uri,
        )],
        &HintTarget::pairing(None),
        &EgressContext::new(EgressKind::Session),
        &opts,
    )
    .await
    .err()
    .expect("sole wt candidate without feature must error");
    assert!(
        err.to_string()
            .contains("webtransport feature is not enabled"),
        "{err}"
    );
}
