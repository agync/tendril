//! Host advertising, the route announcer and client ingest of `0x0C ROUTE_SET` frames.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    IssueOptions, PairingCodeKind, PairingConfig, PairingManager, PairingUri, RouteCheck,
    RoutePolicy,
};
use tendril_core::roster::{
    OperatorEndpoint, Roster, RouteOrigin, RouteSetIgnored, RouteSource, V2PeerSecrets,
};
use tendril_core::routes::RouteSet;
use tendril_core::session::{SessionAction, SessionMachine};
use tendril_core::v2::{PaddingPolicy, V2SessionAction, V2SessionInitiator, V2SessionResponder};
use tendril_runtime::{
    AddressSource, AdvertiseInputs, AdvertiseMode, AnnounceEvent, IngestIgnored, IngestOutcome,
    ListAddrSource, LocalAddr, LocalAddrSource, NetworkSnapshot, RosterAccess, RouteAnnouncer,
    RouteSetLimiter, RouteSetSink, RuntimeError, ServedListener, SnapshotNetwork, StateStore,
    Transport, auto_endpoints, ingest_route_sets,
};

const T0: u64 = 1_795_564_800_000;
const NOW_S: u64 = T0 / 1000;
const SEC: u64 = 1_000;

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn host() -> EndpointIdentity {
    identity(0x20).with_host_id("host-route")
}

fn client() -> EndpointIdentity {
    identity(0x40)
}

fn secrets() -> V2PeerSecrets {
    V2PeerSecrets::new([0x66; 32], [0x77; 32])
}

fn host_roster(cli: &EndpointIdentity) -> Roster {
    let mut roster = Roster::new();
    roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd".into(),
        )
        .unwrap();
    roster.confirm_peer(&cli.device_id(), Some("abcd")).unwrap();
    roster
        .set_peer_v2_secrets(&cli.device_id(), secrets())
        .unwrap();
    roster
}

fn client_roster(host: &EndpointIdentity) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().into(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    roster
        .set_peer_v2_secrets(host.host_id(), secrets())
        .unwrap();
    roster
}

fn explicit(endpoints: &[&str]) -> AdvertiseInputs {
    AdvertiseInputs {
        mode: AdvertiseMode::Explicit,
        advertised_endpoints: endpoints.iter().map(|e| (*e).to_owned()).collect(),
        ..AdvertiseInputs::default()
    }
}

fn announcer(store: RosterAccess, endpoints: &[&str]) -> RouteAnnouncer {
    RouteAnnouncer::new(host(), store, explicit(endpoints), AddressSource::Native)
}

fn la(ip: &str, iface: &str, idx: u32, t: &[Transport]) -> LocalAddr {
    LocalAddr {
        addr: ip.parse().unwrap(),
        iface: iface.into(),
        if_index: idx,
        transports: t.to_vec(),
    }
}

/// The auto-advertise fixture.
fn fixture_addrs() -> Vec<LocalAddr> {
    use Transport::{Cellular, Vpn, Wifi};
    vec![
        la("192.168.1.20", "en0", 2, &[Wifi]),
        la("fd34::9", "en0", 2, &[Wifi]),
        la("fe80::1", "en0", 2, &[Wifi]),
        la("100.101.1.2", "tailscale0", 5, &[Vpn]),
        la("fd7a:115c:a1e0::5", "tailscale0", 5, &[Vpn]),
        la("fd12::5", "wg0", 6, &[Vpn]),
        la("100.70.3.4", "rmnet0", 8, &[Cellular]),
        la("203.0.113.7", "rmnet0", 8, &[Cellular]),
        la("127.0.0.1", "lo", 1, &[]),
    ]
}

fn listener(addr: &str, v6only: Option<bool>) -> ServedListener {
    ServedListener::new(addr.parse().unwrap(), v6only)
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

/// A responder and initiator session pair joined in memory: the sink seals each payload on the
/// host machine and feeds the bytes to the client machine.
enum Machines {
    V1 {
        resp: Box<SessionMachine>,
        init: Box<SessionMachine>,
    },
    V2 {
        resp: Box<V2SessionResponder>,
        init: Box<V2SessionInitiator>,
    },
}

struct LoopSession {
    peer_id: String,
    machines: Mutex<(Machines, Roster)>,
    frames: Mutex<usize>,
}

fn v1_bytes(actions: Vec<SessionAction>) -> Vec<u8> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            SessionAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect()
}

fn v2_bytes(actions: Vec<V2SessionAction>) -> Vec<u8> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            V2SessionAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect()
}

impl LoopSession {
    fn v1(route_seq: Option<u64>) -> Arc<Self> {
        let (host, cli) = (host(), client());
        let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None)
            .unwrap()
            .with_route_seq(route_seq)
            .unwrap();
        let mut resp = SessionMachine::new_responder(&host, None).unwrap();
        let mut hroster = host_roster(&cli);
        let mut croster = client_roster(&host);
        let m1 = v1_bytes(init.start().unwrap());
        let m2 = v1_bytes(resp.feed_bytes(&m1, NOW_S, 1, &mut hroster).unwrap());
        let m3 = v1_bytes(init.feed_bytes(&m2, NOW_S, 2, &mut croster).unwrap());
        resp.feed_bytes(&m3, NOW_S, 3, &mut hroster).unwrap();
        assert!(init.is_established() && resp.is_established());
        assert_eq!(resp.peer_route_seq(), route_seq);
        Self::wrap(
            cli,
            Machines::V1 {
                resp: Box::new(resp),
                init: Box::new(init),
            },
            croster,
        )
    }

    fn v2(route_seq: Option<u64>, padding: Option<PaddingPolicy>) -> Arc<Self> {
        let (host, cli) = (host(), client());
        let mut init = V2SessionInitiator::new(
            &cli,
            host.host_id(),
            *secrets().reconnect_secret(),
            None,
            None,
        )
        .unwrap()
        .with_route_seq(route_seq)
        .unwrap();
        let mut resp = V2SessionResponder::new(&host).unwrap();
        if let Some(p) = padding {
            resp = resp.with_padding_policy(p);
        }
        let mut hroster = host_roster(&cli);
        let mut croster = client_roster(&host);
        let m1 = v2_bytes(init.start(NOW_S).unwrap());
        let m2 = v2_bytes(resp.feed_bytes(&m1, NOW_S, 1, &mut hroster).unwrap());
        let m3 = v2_bytes(init.feed_bytes(&m2, NOW_S, 2, &mut croster).unwrap());
        resp.feed_bytes(&m3, NOW_S, 3, &mut hroster).unwrap();
        assert!(init.is_established() && resp.is_established());
        assert_eq!(resp.peer_route_seq(), route_seq);
        Self::wrap(
            cli,
            Machines::V2 {
                resp: Box::new(resp),
                init: Box::new(init),
            },
            croster,
        )
    }

    fn wrap(cli: EndpointIdentity, machines: Machines, croster: Roster) -> Arc<Self> {
        Arc::new(Self {
            peer_id: cli.device_id(),
            machines: Mutex::new((machines, croster)),
            frames: Mutex::new(0),
        })
    }

    fn sink(self: &Arc<Self>) -> Arc<dyn RouteSetSink> {
        Arc::clone(self) as Arc<dyn RouteSetSink>
    }

    /// Closes the host end (Wire v2 only): later sends fail with core `NotReady`.
    fn close_host(&self) {
        match &mut self.machines.lock().unwrap().0 {
            Machines::V1 { .. } => unreachable!("v2 only"),
            Machines::V2 { resp, .. } => {
                resp.seal_close(0, "bye", 20).unwrap();
            }
        }
    }

    fn frames(&self) -> usize {
        *self.frames.lock().unwrap()
    }

    fn take_route_sets(&self) -> Vec<RouteSet> {
        match &mut self.machines.lock().unwrap().0 {
            Machines::V1 { init, .. } => init.take_route_sets(),
            Machines::V2 { init, .. } => init.take_route_sets(),
        }
    }

    /// Host to client application data still flows and both ends stay established.
    fn assert_open(&self) {
        let (machines, croster) = &mut *self.machines.lock().unwrap();
        match machines {
            Machines::V1 { resp, init } => {
                let wire = v1_bytes(resp.send_data(b"after", 50).unwrap());
                assert_eq!(
                    init.feed_bytes(&wire, NOW_S, 50, croster).unwrap(),
                    vec![SessionAction::AppData(b"after".to_vec())]
                );
                assert!(init.is_established() && resp.is_established());
            }
            Machines::V2 { resp, init } => {
                let wire = v2_bytes(resp.seal_data(b"after", 50).unwrap());
                assert_eq!(
                    init.feed_bytes(&wire, NOW_S, 50, croster).unwrap(),
                    vec![V2SessionAction::AppData(b"after".to_vec())]
                );
                assert!(init.is_established() && resp.is_established());
            }
        }
    }
}

#[async_trait]
impl RouteSetSink for LoopSession {
    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    async fn send_route_set(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        let (machines, croster) = &mut *self.machines.lock().unwrap();
        match machines {
            Machines::V1 { resp, init } => {
                let wire = v1_bytes(resp.send_route_set(payload, 10)?);
                init.feed_bytes(&wire, NOW_S, 10, croster)?;
            }
            Machines::V2 { resp, init } => {
                let wire = v2_bytes(resp.send_route_set(payload, 10)?);
                init.feed_bytes(&wire, NOW_S, 10, croster)?;
            }
        }
        *self.frames.lock().unwrap() += 1;
        Ok(())
    }
}

/// Records sent payloads without a session machine.
struct Spy {
    peer_id: String,
    sent: Mutex<Vec<RouteSet>>,
}

impl Spy {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            peer_id: client().device_id(),
            sent: Mutex::new(Vec::new()),
        })
    }

    fn seqs(&self) -> Vec<u64> {
        self.sent.lock().unwrap().iter().map(|s| s.seq).collect()
    }
}

#[async_trait]
impl RouteSetSink for Spy {
    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    async fn send_route_set(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        self.sent.lock().unwrap().push(RouteSet::decode(payload)?);
        Ok(())
    }
}

/// A sink whose every send fails with `err()`.
struct FailingSink {
    peer_id: String,
    err: fn() -> RuntimeError,
}

#[async_trait]
impl RouteSetSink for FailingSink {
    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    async fn send_route_set(&self, _payload: &[u8]) -> Result<(), RuntimeError> {
        Err((self.err)())
    }
}

fn failing(peer_id: String, err: fn() -> RuntimeError) -> Arc<dyn RouteSetSink> {
    Arc::new(FailingSink { peer_id, err })
}

#[tokio::test]
async fn failed_first_delivery_fails_registration() {
    let ann = announcer(host_store(), &["192.168.1.100:9100"]);
    ann.publish(T0).unwrap();
    let peer = client().device_id();

    let closed = failing(peer.clone(), || RuntimeError::Closed);
    let err = ann
        .on_session_established(&closed, Some(0), T0)
        .await
        .expect_err("a failed initial route set fails the registration");
    assert!(matches!(err, RuntimeError::Closed), "{err}");

    let unsendable = failing(peer.clone(), || {
        RuntimeError::Core(CoreError::FrameTooLarge { len: 9_000, max: 1 })
    });
    ann.on_session_established(&unsendable, Some(0), T0)
        .await
        .expect("an unsendable set keeps the session");
    let stranger = failing("not-a-peer".into(), || RuntimeError::Closed);
    ann.on_session_established(&stranger, Some(0), T0)
        .await
        .expect("an inactive peer is recorded, not an error");
    let events = ann.take_events();
    assert!(
        matches!(
            events.as_slice(),
            [
                AnnounceEvent::SendFailed { .. },
                AnnounceEvent::Unsendable { .. },
                AnnounceEvent::PeerInactive { .. },
            ]
        ),
        "{events:?}"
    );
}

fn host_store() -> RosterAccess {
    RosterAccess::memory(host_roster(&client()))
}

fn set_endpoints(a: &RouteAnnouncer, endpoints: &[&str]) {
    a.set_inputs(explicit(endpoints));
}

#[test]
fn auto_advertise_follows_listener_coverage_and_overlay_evidence() {
    let src = ListAddrSource::new(fixture_addrs());
    let a = listener("0.0.0.0:9100", None);
    let b_v6 = listener("[::]:9200", Some(true));
    let b_dual = listener("[::]:9200", Some(false));

    assert_eq!(
        auto_endpoints(&[a], &src),
        strings(&["direct:192.168.1.20:9100", "overlay://100.101.1.2:9100"])
    );
    assert_eq!(
        auto_endpoints(&[b_v6], &src),
        strings(&[
            "direct:[fd34::9]:9200",
            "overlay://[fd7a:115c:a1e0::5]:9200",
            "overlay://[fd12::5]:9200",
        ])
    );
    let dual = auto_endpoints(&[b_dual], &src);
    assert_eq!(
        dual,
        strings(&[
            "direct:192.168.1.20:9200",
            "direct:[fd34::9]:9200",
            "overlay://100.101.1.2:9200",
            "overlay://[fd7a:115c:a1e0::5]:9200",
            "overlay://[fd12::5]:9200",
        ])
    );
    let all = auto_endpoints(&[a, b_dual], &src);
    for never in ["100.70.3.4", "203.0.113.7", "fe80::1", "127.0.0.1"] {
        assert!(
            !all.iter().any(|h| h.contains(never)),
            "{never} must never be auto-advertised: {all:?}"
        );
    }
    let cgnat_wifi = ListAddrSource::new(vec![la("100.70.3.5", "wlan0", 3, &[Transport::Wifi])]);
    assert!(
        auto_endpoints(&[a], &cgnat_wifi).is_empty(),
        "100.64.0.0/10 without overlay evidence is not an overlay"
    );
    let concrete = [listener("192.168.1.20:9300", None)];
    assert!(auto_endpoints(&concrete, &src).is_empty());
}

#[test]
fn auto_advertise_feeds_the_announced_set_and_a_signed_remote_uri() {
    let source: Arc<dyn LocalAddrSource + Send + Sync> =
        Arc::new(ListAddrSource::new(fixture_addrs()));
    let inputs = AdvertiseInputs {
        mode: AdvertiseMode::Auto,
        served_endpoints: strings(&["0.0.0.0:9100", "[::]:9200"]),
        listeners: vec![
            listener("0.0.0.0:9100", None),
            listener("[::]:9200", Some(false)),
        ],
        advertised_endpoints: vec![],
    };
    let ann = RouteAnnouncer::new(
        host(),
        host_store(),
        inputs.clone(),
        AddressSource::Custom(Arc::clone(&source)),
    );
    let state = ann.publish(T0).unwrap();
    let overlays: Vec<&String> = state
        .routes()
        .iter()
        .filter(|h| h.starts_with("overlay://"))
        .collect();
    assert_eq!(
        overlays,
        ["overlay://100.101.1.2:9100", "overlay://100.101.1.2:9200"],
        "provider cap keeps two overlay hints, IPv4 first"
    );
    assert!(
        state
            .routes()
            .iter()
            .all(|h| auto_endpoints(&inputs.listeners, source.as_ref()).contains(h))
    );
    assert!(
        ann.last_dropped()
            .iter()
            .all(|d| d.hint.starts_with("overlay://") || d.hint.starts_with("direct:")),
        "unspecified binds are expanded, not reported: {:?}",
        ann.last_dropped()
    );

    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    let issued = ann
        .issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), T0)
        .unwrap();
    assert_eq!(issued.code_kind, PairingCodeKind::Remote3Group);
    assert_eq!(issued.route_seq, Some(state.seq()));
    let parsed = PairingUri::parse(&issued.uri).unwrap();
    let RouteCheck::Verified(statement) =
        parsed.verify_route_statement(host().signing_key().public_key())
    else {
        panic!("issued URI must be host-signed");
    };
    assert!(statement.hints().iter().all(|h| state.routes().contains(h)));
    assert!(!statement.hints().is_empty());
    assert!(
        issued.dropped.starts_with(&ann.last_dropped()),
        "announced-set drops come first in the issued report"
    );

    let explicit_inputs = AdvertiseInputs {
        mode: AdvertiseMode::Explicit,
        served_endpoints: strings(&["0.0.0.0:9100", "192.168.1.20:9300"]),
        ..inputs
    };
    ann.set_inputs(explicit_inputs);
    let state = ann.publish(T0 + SEC).unwrap();
    assert_eq!(state.routes(), strings(&["direct:192.168.1.20:9300"]));
    assert!(
        ann.last_dropped().iter().any(|d| d.hint == "0.0.0.0:9100"),
        "explicit mode reports the unspecified bind"
    );
}

fn snapshot(networks: &[(&str, Transport, &[&str])]) -> NetworkSnapshot {
    NetworkSnapshot {
        networks: networks
            .iter()
            .enumerate()
            .map(|(i, (iface, t, addrs))| SnapshotNetwork {
                id: format!("net{i}"),
                iface: (*iface).into(),
                if_index: u32::try_from(i).unwrap() + 2,
                transports: vec![*t],
                addrs: strings(addrs),
            })
            .collect(),
    }
}

fn wifi_vpn() -> NetworkSnapshot {
    snapshot(&[
        ("wlan0", Transport::Wifi, &["192.168.1.20/24"]),
        ("tun0", Transport::Vpn, &["100.101.1.2/32"]),
    ])
}

fn vpn_only() -> NetworkSnapshot {
    snapshot(&[("tun0", Transport::Vpn, &["100.101.1.2/32"])])
}

fn snapshot_announcer() -> RouteAnnouncer {
    let inputs = AdvertiseInputs {
        mode: AdvertiseMode::Auto,
        served_endpoints: strings(&["0.0.0.0:9100"]),
        listeners: vec![listener("0.0.0.0:9100", None)],
        advertised_endpoints: vec![],
    };
    RouteAnnouncer::new(host(), host_store(), inputs, AddressSource::Snapshot)
}

#[test]
fn snapshot_source_retains_the_last_snapshot() {
    let ann = snapshot_announcer();
    let first = ann.refresh(T0, Some(wifi_vpn())).unwrap();
    assert_eq!(
        first.state.routes(),
        strings(&["direct:192.168.1.20:9100", "overlay://100.101.1.2:9100"])
    );
    assert!(first.changed);

    let timer = ann.refresh(T0 + 60 * SEC, None).unwrap();
    assert!(!timer.changed);
    assert_eq!(timer.route_seq(), first.route_seq());

    let lost_wifi = ann.refresh(T0 + 61 * SEC, Some(vpn_only())).unwrap();
    assert!(lost_wifi.changed);
    assert_eq!(
        lost_wifi.state.routes(),
        strings(&["overlay://100.101.1.2:9100"])
    );

    let empty = ann
        .refresh(T0 + 62 * SEC, Some(NetworkSnapshot::default()))
        .unwrap();
    assert!(
        !empty.changed,
        "a transient zero-network snapshot is not applied"
    );
    assert_eq!(empty.route_seq(), lost_wifi.route_seq());

    let back = ann.refresh(T0 + 63 * SEC, Some(wifi_vpn())).unwrap();
    assert!(back.changed);
    assert_eq!(back.route_seq(), lost_wifi.route_seq() + 1);
    assert_eq!(
        ann.next_deadline_ms(),
        None,
        "the pending empty snapshot was cleared"
    );
}

#[tokio::test]
async fn lost_last_network_is_retired_after_the_debounce() {
    let ann = snapshot_announcer();
    let spy = Spy::new();
    ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(0), T0)
        .await
        .unwrap();
    let start = ann.refresh(T0, Some(wifi_vpn())).unwrap();
    ann.flush(T0 + 2 * SEC).await;
    assert_eq!(spy.seqs(), vec![start.route_seq()]);

    let lost = T0 + 40 * SEC;
    let r = ann.refresh(lost, Some(NetworkSnapshot::default())).unwrap();
    assert!(!r.changed);
    assert_eq!(ann.next_deadline_ms(), Some(lost + 30 * SEC));
    let r = ann.refresh(lost + 29 * SEC, None).unwrap();
    assert!(
        !r.changed,
        "inside the debounce the timer keeps the last networks"
    );

    let r = ann.refresh(lost + 30 * SEC, None).unwrap();
    assert!(r.changed, "a confirmed empty snapshot is published");
    assert!(r.state.routes().is_empty());
    ann.flush(lost + 32 * SEC).await;
    assert_eq!(spy.seqs(), vec![start.route_seq(), r.route_seq()]);
    assert!(spy.sent.lock().unwrap()[1].routes.is_empty());
}

#[tokio::test]
async fn issuance_bump_reaches_live_sessions() {
    for v2 in [false, true] {
        let ann = announcer(host_store(), &["192.168.1.21:9100"]);
        for (i, ep) in ["192.168.1.22:9100", "192.168.1.23:9100"]
            .iter()
            .enumerate()
        {
            ann.publish(T0).unwrap();
            set_endpoints(&ann, &[ep]);
            assert_eq!(ann.publish(T0).unwrap().seq(), i as u64 + 2);
        }
        let session = if v2 {
            LoopSession::v2(Some(3), None)
        } else {
            LoopSession::v1(Some(3))
        };
        ann.on_session_established(&session.sink(), Some(3), T0)
            .await
            .unwrap();
        assert_eq!(
            session.frames(),
            0,
            "a client at the current seq gets nothing"
        );

        set_endpoints(&ann, &["192.168.1.24:9100"]);
        let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
        let issued = ann
            .issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), T0 + SEC)
            .unwrap();
        assert_eq!(issued.route_seq, Some(4));

        let r = ann.refresh(T0 + 5 * SEC, None).unwrap();
        assert!(!r.changed);
        ann.flush(T0 + 5 * SEC).await;
        assert_eq!(session.frames(), 1);
        let sets = session.take_route_sets();
        assert_eq!(sets.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![4]);
        assert_eq!(sets[0].routes, strings(&["direct:192.168.1.24:9100"]));
    }
}

#[tokio::test]
async fn host_rate_limit_debounces_and_coalesces() {
    let ann = announcer(host_store(), &["192.168.1.30:9100"]);
    let base = ann.publish(T0).unwrap().seq();
    let spy = Spy::new();
    ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(base), T0)
        .await
        .unwrap();

    let mut t = T0 + 100 * SEC;
    let changes: Vec<u64> = (0..5).map(|i| t + i * 2_500).collect();
    let mut last_seq = base;
    while t <= T0 + 140 * SEC {
        if let Some(i) = changes.iter().position(|c| *c == t) {
            set_endpoints(&ann, &[&format!("192.168.1.{}:9100", 31 + i)]);
            last_seq = ann.publish(t).unwrap().seq();
        }
        ann.flush(t).await;
        t += 500;
    }
    assert_eq!(spy.seqs(), vec![base + 1, last_seq]);
    assert_eq!(last_seq, base + 5);
    let sent = ann
        .take_events()
        .into_iter()
        .filter(|e| matches!(e, AnnounceEvent::Sent { .. }))
        .count();
    assert_eq!(sent, 2);
}

#[tokio::test]
async fn host_rate_limit_timing() {
    let ann = announcer(host_store(), &["192.168.1.30:9100"]);
    let base = ann.publish(T0).unwrap().seq();
    let spy = Spy::new();
    ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(base), T0)
        .await
        .unwrap();
    set_endpoints(&ann, &["192.168.1.31:9100"]);
    ann.publish(T0 + SEC).unwrap();
    assert_eq!(ann.next_deadline_ms(), Some(T0 + 3 * SEC));
    ann.flush(T0 + 3 * SEC - 1).await;
    assert!(spy.seqs().is_empty(), "debounced");
    ann.flush(T0 + 3 * SEC).await;
    assert_eq!(spy.seqs(), vec![base + 1]);

    set_endpoints(&ann, &["192.168.1.32:9100"]);
    ann.publish(T0 + 4 * SEC).unwrap();
    assert_eq!(ann.next_deadline_ms(), Some(T0 + 33 * SEC));
    ann.flush(T0 + 33 * SEC - 1).await;
    assert_eq!(spy.seqs().len(), 1);
    ann.flush(T0 + 33 * SEC).await;
    assert_eq!(spy.seqs(), vec![base + 1, base + 2]);
    assert_eq!(ann.next_deadline_ms(), None);
}

/// A client entry that stored route A from the host's signed URI at `seq = 1`.
fn paired_client(ann: &RouteAnnouncer) -> RosterAccess {
    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    let issued = ann
        .issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), T0)
        .unwrap();
    let h = host();
    let RouteCheck::Verified(statement) = PairingUri::parse(&issued.uri)
        .unwrap()
        .verify_route_statement(h.signing_key().public_key())
    else {
        panic!("signed URI");
    };
    let mut roster = client_roster(&h);
    assert!(
        roster
            .replace_signed_routes(h.host_id(), &statement)
            .unwrap()
    );
    roster
        .set_routes(
            h.host_id(),
            vec![OperatorEndpoint {
                hint: "direct:10.9.9.9:9100".into(),
                relay_key: None,
            }],
        )
        .unwrap();
    RosterAccess::memory(roster)
}

fn routes_of(store: &RosterAccess, source: RouteSource) -> Vec<String> {
    store
        .load()
        .unwrap()
        .get(host().host_id())
        .unwrap()
        .routes
        .iter()
        .filter(|r| r.source == source)
        .map(|r| r.hint.clone())
        .collect()
}

#[tokio::test]
async fn day2_announced_routes_replace_stale_ones() {
    const A: &str = "direct:192.168.1.40:9100";
    const B: &str = "direct:192.168.1.41:9100";
    for v2 in [false, true] {
        let ann = announcer(host_store(), &["192.168.1.40:9100"]);
        let cli = paired_client(&ann);
        assert_eq!(routes_of(&cli, RouteSource::Signed), strings(&[A]));
        let meta = cli
            .load()
            .unwrap()
            .get(host().host_id())
            .unwrap()
            .route_meta;
        assert_eq!(meta.map(|m| (m.seq, m.origin)), Some((1, RouteOrigin::Uri)));

        let session = if v2 {
            LoopSession::v2(Some(0), None)
        } else {
            LoopSession::v1(Some(0))
        };
        ann.on_session_established(&session.sink(), Some(0), T0)
            .await
            .unwrap();
        assert_eq!(
            session.frames(),
            1,
            "seq 1 > route_seq 0: sent on establishment"
        );
        let mut limiter = RouteSetLimiter::new();
        let out = ingest_route_sets(
            &cli,
            host().host_id(),
            session.take_route_sets(),
            RoutePolicy::AllSigned,
            &mut limiter,
            T0,
        )
        .unwrap();
        assert!(matches!(out[..], [IngestOutcome::Applied { seq: 1, .. }]));

        set_endpoints(&ann, &["192.168.1.41:9100"]);
        let refreshed = ann.refresh(T0 + 10 * SEC, None).unwrap();
        assert_eq!(refreshed.route_seq(), 2);
        ann.flush(T0 + 12 * SEC).await;
        assert_eq!(session.frames(), 1, "the 30 s interval holds the change");
        ann.flush(T0 + 30 * SEC).await;
        assert_eq!(session.frames(), 2);
        let out = ingest_route_sets(
            &cli,
            host().host_id(),
            session.take_route_sets(),
            RoutePolicy::AllSigned,
            &mut limiter,
            T0 + 30 * SEC,
        )
        .unwrap();
        assert_eq!(
            out,
            vec![IngestOutcome::Applied {
                seq: 2,
                added: strings(&[B]),
                removed: strings(&[A]),
            }]
        );
        assert_eq!(routes_of(&cli, RouteSource::Signed), strings(&[B]));
        assert_eq!(
            routes_of(&cli, RouteSource::Operator),
            strings(&["direct:10.9.9.9:9100"])
        );
        let meta = cli
            .load()
            .unwrap()
            .get(host().host_id())
            .unwrap()
            .route_meta;
        assert_eq!(
            meta.map(|m| (m.seq, m.origin)),
            Some((2, RouteOrigin::Session))
        );
        let last = cli.last_route_set(host().host_id()).unwrap();
        assert_eq!((last.outcome, last.seq), ("applied", 2));
        session.assert_open();
    }
}

#[tokio::test]
async fn stale_and_forged_route_sets_are_ignored_and_the_session_stays_open() {
    for v2 in [false, true] {
        let ann = announcer(host_store(), &["192.168.1.50:9100"]);
        let cli = paired_client(&ann);
        set_endpoints(&ann, &["192.168.1.51:9100"]);
        let current = ann.publish(T0).unwrap();
        let replay = RouteSet::sign(&host(), 1, NOW_S, strings(&["direct:192.168.1.50:9100"]))
            .unwrap()
            .encode();
        let mut forged = RouteSet::sign(&host(), 9, NOW_S, strings(&["direct:192.168.1.52:9100"]))
            .unwrap()
            .encode();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;

        let session = if v2 {
            LoopSession::v2(Some(1), None)
        } else {
            LoopSession::v1(Some(1))
        };
        ann.on_session_established(&session.sink(), Some(1), T0)
            .await
            .unwrap();
        let mut limiter = RouteSetLimiter::new();
        let out = ingest_route_sets(
            &cli,
            host().host_id(),
            session.take_route_sets(),
            RoutePolicy::AllSigned,
            &mut limiter,
            T0,
        )
        .unwrap();
        assert!(matches!(out[..], [IngestOutcome::Applied { seq: 2, .. }]));
        let before = cli.load().unwrap();

        let mut at = T0;
        for (payload, reason) in [
            (&replay, RouteSetIgnored::StaleSeq),
            (&forged, RouteSetIgnored::BadSignature),
        ] {
            at += 11 * SEC;
            session.send_route_set(payload).await.unwrap();
            let out = ingest_route_sets(
                &cli,
                host().host_id(),
                session.take_route_sets(),
                RoutePolicy::AllSigned,
                &mut limiter,
                at,
            )
            .unwrap();
            let seq = RouteSet::decode(payload).unwrap().seq;
            assert_eq!(
                out,
                vec![IngestOutcome::Ignored {
                    seq,
                    reason: IngestIgnored::Rejected(reason),
                }]
            );
            assert_eq!(
                cli.last_route_set(host().host_id()).map(|l| l.outcome),
                Some(reason.as_str())
            );
            assert_eq!(
                serde_json::to_value(cli.load().unwrap()).unwrap(),
                serde_json::to_value(&before).unwrap(),
                "routes unchanged"
            );
            session.assert_open();
        }
        assert_eq!(current.seq(), 2);
    }
}

#[tokio::test]
async fn client_rate_limit_processes_at_most_one_set_per_window() {
    let ann = announcer(host_store(), &["192.168.1.60:9100"]);
    let cli = paired_client(&ann);
    let mut limiter = RouteSetLimiter::new();
    let mut processed = Vec::new();
    for i in 0..40u64 {
        let set = RouteSet::sign(
            &host(),
            2 + i,
            NOW_S,
            strings(&["direct:192.168.1.61:9100"]),
        )
        .unwrap();
        let now = T0 + i * 500;
        for out in ingest_route_sets(
            &cli,
            host().host_id(),
            vec![set],
            RoutePolicy::AllSigned,
            &mut limiter,
            now,
        )
        .unwrap()
        {
            if !matches!(
                out,
                IngestOutcome::Ignored {
                    reason: IngestIgnored::RateLimited,
                    ..
                }
            ) {
                processed.push(now);
            }
        }
    }
    assert_eq!(processed, vec![T0, T0 + 10 * SEC]);

    let mut batch_limiter = RouteSetLimiter::new();
    let batch: Vec<RouteSet> = (50..54)
        .map(|seq| {
            RouteSet::sign(&host(), seq, NOW_S, strings(&["direct:192.168.1.62:9100"])).unwrap()
        })
        .collect();
    let out = ingest_route_sets(
        &cli,
        host().host_id(),
        batch,
        RoutePolicy::AllSigned,
        &mut batch_limiter,
        T0 + 100 * SEC,
    )
    .unwrap();
    let applied: Vec<u64> = out
        .iter()
        .filter_map(|o| match o {
            IngestOutcome::Applied { seq, .. } => Some(*seq),
            IngestOutcome::Ignored { .. } => None,
        })
        .collect();
    assert_eq!(
        applied,
        vec![53],
        "the newest set of a burst is the one processed"
    );
}

#[tokio::test]
async fn sessions_without_route_seq_never_receive_route_sets() {
    for v2 in [false, true] {
        let ann = announcer(host_store(), &["192.168.1.70:9100"]);
        let cli = paired_client(&ann);
        let session = if v2 {
            LoopSession::v2(None, None)
        } else {
            LoopSession::v1(None)
        };
        ann.on_session_established(&session.sink(), None, T0)
            .await
            .unwrap();
        for i in 1..=60u64 {
            set_endpoints(&ann, &[&format!("192.168.1.{}:9100", 70 + (i % 2))]);
            ann.refresh(T0 + i * SEC, None).unwrap();
            ann.flush(T0 + i * SEC).await;
        }
        assert_eq!(session.frames(), 0);
        assert!(ann.take_events().is_empty(), "no send was attempted");
        session.assert_open();

        let before = serde_json::to_value(cli.load().unwrap()).unwrap();
        let forced =
            RouteSet::sign(&host(), 99, NOW_S, strings(&["direct:192.168.1.79:9100"])).unwrap();
        for policy in [RoutePolicy::CommittedOnly, RoutePolicy::None] {
            let out = ingest_route_sets(
                &cli,
                host().host_id(),
                vec![forced.clone()],
                policy,
                &mut RouteSetLimiter::new(),
                T0,
            )
            .unwrap();
            assert!(out.is_empty());
        }
        assert_eq!(serde_json::to_value(cli.load().unwrap()).unwrap(), before);
        assert_eq!(cli.last_route_set(host().host_id()), None);
    }
}

#[tokio::test]
async fn v2_bucket_too_small_is_reported_and_the_session_stays_open() {
    let ann = announcer(host_store(), &["192.168.1.80:9100"]);
    ann.publish(T0).unwrap();
    let small = PaddingPolicy::with_buckets(vec![256, 1_024], true).unwrap();
    let session = LoopSession::v2(Some(0), Some(small));
    ann.on_session_established(&session.sink(), Some(0), T0)
        .await
        .unwrap();
    assert_eq!(session.frames(), 0);
    assert_eq!(
        ann.take_events(),
        vec![AnnounceEvent::Unsendable {
            peer_id: client().device_id(),
            seq: 1,
            reason: "bucket_too_small",
        }]
    );
    ann.flush(T0 + 60 * SEC).await;
    assert!(
        ann.take_events().is_empty(),
        "a reported seq is not retried"
    );
    session.assert_open();
}

#[tokio::test]
async fn inactive_peer_is_skipped_before_sealing() {
    let store = host_store();
    let ann = announcer(store.clone(), &["192.168.1.90:9100"]);
    ann.publish(T0).unwrap();
    let spy = Spy::new();
    ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(1), T0)
        .await
        .unwrap();
    store
        .update(|r| Ok(r.revoke_peer(&client().device_id())?))
        .unwrap();
    set_endpoints(&ann, &["192.168.1.91:9100"]);
    ann.publish(T0 + SEC).unwrap();
    ann.flush(T0 + 3 * SEC).await;
    assert!(spy.seqs().is_empty());
    assert_eq!(
        ann.take_events(),
        vec![AnnounceEvent::PeerInactive {
            peer_id: client().device_id(),
            seq: 2,
        }]
    );
}

#[tokio::test]
async fn dropped_sessions_are_forgotten() {
    let ann = announcer(host_store(), &["192.168.1.92:9100"]);
    ann.publish(T0).unwrap();
    let spy = Spy::new();
    ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(1), T0)
        .await
        .unwrap();
    drop(spy);
    set_endpoints(&ann, &["192.168.1.93:9100"]);
    ann.publish(T0 + SEC).unwrap();
    assert_eq!(ann.next_deadline_ms(), None);
}

fn restart_round(store: &RosterAccess, endpoint: &str) -> (u64, usize) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let ann = announcer(store.clone(), &[endpoint]);
        let seq = ann.publish(T0).unwrap().seq();
        let spy = Spy::new();
        ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(3), T0)
            .await
            .unwrap();
        (seq, spy.seqs().len())
    })
}

#[test]
fn host_restart_keeps_seq_monotonic() {
    for sealed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let open = || {
            let store = if sealed {
                StateStore::open_sealed(dir.path(), &host()).unwrap()
            } else {
                StateStore::open_or_create(dir.path()).unwrap()
            };
            assert_eq!(store.is_sealed(), sealed);
            RosterAccess::from_store(Arc::new(store)).unwrap()
        };
        let access = open();
        access
            .update(|r| {
                *r = host_roster(&client());
                Ok(())
            })
            .unwrap();
        for (i, ep) in ["192.168.2.1:9100", "192.168.2.2:9100", "192.168.2.3:9100"]
            .iter()
            .enumerate()
        {
            assert_eq!(restart_round(&access, ep).0, i as u64 + 1);
        }
        drop(access);

        let access = open();
        assert_eq!(
            restart_round(&access, "192.168.2.3:9100"),
            (3, 0),
            "unchanged set after restart: same seq, nothing for a client at 3"
        );
        assert_eq!(restart_round(&access, "192.168.2.4:9100"), (4, 1));
    }
}

#[tokio::test]
async fn exhausted_sequence_stops_announcing() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open_or_create(dir.path()).unwrap();
    store.save_roster(&host_roster(&client())).unwrap();
    let access = RosterAccess::from_store(Arc::new(store.clone())).unwrap();
    announcer(access.clone(), &["192.168.3.1:9100"])
        .publish(T0)
        .unwrap();
    let path = store.roster_path();
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    json["local_routes"]["seq"] = serde_json::json!(9_007_199_254_740_991_u64);
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();

    let ann = announcer(access, &["192.168.3.1:9100"]);
    assert_eq!(ann.publish(T0).unwrap().seq(), 9_007_199_254_740_991);
    let spy = Spy::new();
    ann.on_session_established(&(Arc::clone(&spy) as Arc<dyn RouteSetSink>), Some(5), T0)
        .await
        .unwrap();
    assert_eq!(
        spy.seqs(),
        vec![9_007_199_254_740_991],
        "the capped set is still sent"
    );

    set_endpoints(&ann, &["192.168.3.2:9100", "0.0.0.0:9"]);
    let err = ann.publish(T0 + SEC).unwrap_err();
    assert!(matches!(
        err,
        RuntimeError::Core(CoreError::ProtocolViolation("route sequence exhausted"))
    ));
    assert!(ann.take_events().contains(&AnnounceEvent::SeqExhausted));
    assert!(
        ann.last_dropped().is_empty(),
        "a failed publish keeps the last published drops: {:?}",
        ann.last_dropped()
    );
    ann.flush(T0 + 60 * SEC).await;
    assert_eq!(spy.seqs().len(), 1);

    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    assert!(
        ann.issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), T0 + SEC)
            .is_err()
    );
    let unsigned = ann
        .issue_pairing_uri(
            &mgr,
            "Studio",
            IssueOptions {
                sign_routes: false,
                ..IssueOptions::default()
            },
            T0 + SEC,
        )
        .unwrap();
    assert_eq!(unsigned.route_seq, None);
    assert!(
        unsigned.dropped.iter().all(|d| d.hint != "0.0.0.0:9"),
        "the fallback reports the stored set's drops, not the failed set's: {:?}",
        unsigned.dropped
    );
    assert_eq!(
        unsigned.parsed.endpoints,
        strings(&["direct:192.168.3.1:9100"])
    );
}

#[test]
fn served_listener_reads_v6only_back() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let v4 = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let l = ServedListener::from_listener(&v4).unwrap();
        assert_eq!(l.v6only(), None);
        assert!(l.is_unspecified());
        let src = ListAddrSource::new(vec![
            la("192.168.1.20", "en0", 2, &[Transport::Wifi]),
            la("fd34::9", "en0", 2, &[Transport::Wifi]),
        ]);
        for only in [true, false] {
            let Ok(sock) = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)
            else {
                return;
            };
            sock.set_only_v6(only).unwrap();
            let any6: std::net::SocketAddr = "[::]:0".parse().unwrap();
            if sock.bind(&any6.into()).is_err() {
                return;
            }
            sock.listen(4).unwrap();
            sock.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(sock.into()).unwrap();
            let served = ServedListener::from_listener(&listener).unwrap();
            assert_eq!(served.v6only(), Some(only));
            let has_v4 = auto_endpoints(&[served], &src)
                .iter()
                .filter_map(|h| {
                    h.strip_prefix("direct:")?
                        .parse::<std::net::SocketAddr>()
                        .ok()
                })
                .any(|s| s.ip().is_ipv4());
            assert_eq!(has_v4, !only);
        }
    });
}

#[cfg(feature = "auto-advertise")]
#[test]
fn native_source_never_reports_loopback() {
    let addrs = tendril_runtime::NativeAddrSource.local_addrs();
    assert!(addrs.iter().all(|a| !a.addr.is_loopback()));
}

#[test]
fn auto_advertise_orders_ipv4_first_across_listeners() {
    use Transport::Wifi;
    let src: Arc<dyn LocalAddrSource + Send + Sync> = Arc::new(ListAddrSource::new(vec![
        la("fd34::9", "en0", 2, &[Wifi]),
        la("fd34::10", "en0", 2, &[Wifi]),
        la("192.168.1.20", "en0", 2, &[Wifi]),
    ]));
    let listeners = vec![
        listener("[::]:9200", Some(true)),
        listener("0.0.0.0:9100", None),
    ];
    assert_eq!(
        auto_endpoints(&listeners, src.as_ref()),
        strings(&[
            "direct:192.168.1.20:9100",
            "direct:[fd34::9]:9200",
            "direct:[fd34::10]:9200",
        ]),
        "IPv4 before IPv6 across listeners, whatever their order"
    );
    let inputs = AdvertiseInputs {
        mode: AdvertiseMode::Auto,
        served_endpoints: strings(&["[::]:9200", "0.0.0.0:9100"]),
        listeners,
        advertised_endpoints: vec![],
    };
    let ann = RouteAnnouncer::new(host(), host_store(), inputs, AddressSource::Custom(src));
    assert_eq!(
        ann.publish(T0).unwrap().routes(),
        strings(&["direct:192.168.1.20:9100", "direct:[fd34::9]:9200"]),
        "the Direct cap keeps the IPv4 LAN hint"
    );
}

#[test]
fn private_address_on_a_tunnel_interface_is_not_lan() {
    use Transport::{Ethernet, Wifi};
    let src = ListAddrSource::new(vec![
        la("10.8.0.2", "wg0", 7, &[Ethernet]),
        la("172.16.4.2", "tun0", 8, &[Wifi]),
        la("fd55::2", "utun3", 9, &[Ethernet]),
        la("192.168.1.20", "en0", 2, &[Wifi]),
    ]);
    let listeners = [
        listener("0.0.0.0:9100", None),
        listener("[::]:9200", Some(true)),
    ];
    assert_eq!(
        auto_endpoints(&listeners, &src),
        strings(&["direct:192.168.1.20:9100", "overlay://[fd55::2]:9200"]),
        "overlay evidence (a tunnel name) rules out LAN even without Transport::Vpn"
    );
}

fn issued_hints(issued: &tendril_core::pairing::IssuedPairingUri) -> Vec<String> {
    issued.parsed.endpoints.clone()
}

#[test]
fn publish_and_issuance_apply_a_matured_empty_snapshot() {
    const RELAY: &str = "wss://relay.example.com/v1/relay";
    let inputs = AdvertiseInputs {
        mode: AdvertiseMode::Auto,
        served_endpoints: strings(&["0.0.0.0:9100"]),
        listeners: vec![listener("0.0.0.0:9100", None)],
        advertised_endpoints: strings(&[RELAY]),
    };
    let ann = RouteAnnouncer::new(host(), host_store(), inputs, AddressSource::Snapshot);
    let start = ann.refresh(T0, Some(wifi_vpn())).unwrap();
    assert!(start.state.routes().len() > 1);
    let lost = T0 + SEC;
    assert!(
        !ann.refresh(lost, Some(NetworkSnapshot::default()))
            .unwrap()
            .changed
    );
    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    let inside = ann
        .issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), lost + 29 * SEC)
        .unwrap();
    assert_eq!(inside.route_seq, Some(start.route_seq()));
    assert!(issued_hints(&inside).contains(&"direct:192.168.1.20:9100".to_owned()));

    let after = ann
        .issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), lost + 30 * SEC)
        .unwrap();
    assert_eq!(
        after.route_seq,
        Some(start.route_seq() + 1),
        "issuance after the debounce publishes the confirmed empty snapshot"
    );
    assert_eq!(issued_hints(&after), strings(&[RELAY]));
    assert_eq!(ann.next_deadline_ms(), None);

    let ann = snapshot_announcer();
    ann.refresh(T0, Some(wifi_vpn())).unwrap();
    ann.refresh(lost, Some(NetworkSnapshot::default())).unwrap();
    assert!(
        ann.publish(lost + 30 * SEC).unwrap().routes().is_empty(),
        "a plain publish after the debounce retires the lost addresses"
    );
}

#[tokio::test]
async fn closed_session_is_evicted_and_not_negotiated_is_kept() {
    let ann = announcer(host_store(), &["192.168.1.100:9100"]);
    let closed = LoopSession::v2(Some(0), None);
    ann.on_session_established(&closed.sink(), Some(0), T0)
        .await
        .unwrap();
    closed.close_host();
    // A v1 session whose client sent no `route_seq`, registered as if it had: core reports
    // "peer did not negotiate route sets".
    let unnegotiated = LoopSession::v1(None);
    ann.on_session_established(&unnegotiated.sink(), Some(0), T0)
        .await
        .unwrap();
    assert!(ann.take_events().is_empty());

    ann.publish(T0).unwrap();
    ann.flush(T0 + 2 * SEC).await;
    let peer_id = client().device_id();
    assert_eq!(
        ann.take_events(),
        vec![
            AnnounceEvent::SendFailed {
                peer_id: peer_id.clone(),
                seq: 1,
            },
            AnnounceEvent::Unsendable {
                peer_id: peer_id.clone(),
                seq: 1,
                reason: "not_negotiated",
            },
        ],
        "a closed session's NotReady is a send failure"
    );

    set_endpoints(&ann, &["192.168.1.101:9100"]);
    ann.publish(T0 + 3 * SEC).unwrap();
    ann.flush(T0 + 40 * SEC).await;
    assert_eq!(
        ann.take_events(),
        vec![AnnounceEvent::Unsendable {
            peer_id,
            seq: 2,
            reason: "not_negotiated",
        }],
        "the closed session was evicted; the open one stays registered"
    );
    unnegotiated.assert_open();
}

fn wall_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[tokio::test]
async fn spawn_runs_one_timer_task_that_ends_with_the_announcer() {
    let ann = Arc::new(announcer(host_store(), &["192.168.1.110:9100"]));
    let first = ann.spawn(None);
    let second = ann.spawn(None);
    tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("a second spawn returns a finished task")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!first.is_finished(), "the first timer keeps running");

    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let third = ann.spawn(None);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!third.is_finished(), "an aborted timer can be replaced");

    let spy = Spy::new();
    let sink = Arc::clone(&spy) as Arc<dyn RouteSetSink>;
    ann.on_session_established(&sink, Some(0), wall_ms())
        .await
        .unwrap();
    ann.publish(wall_ms()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while spy.seqs().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the timer sends the published set after the debounce");
    assert_eq!(spy.seqs(), vec![1]);

    drop(ann);
    tokio::time::timeout(Duration::from_secs(2), third)
        .await
        .expect("the timer task ends with the announcer")
        .unwrap();
}

#[test]
fn ignored_sets_are_not_written_and_failed_writes_keep_the_window() {
    let ann = announcer(host_store(), &["192.168.1.120:9100"]);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::open_or_create(dir.path()).unwrap());
    store
        .save_roster(&paired_client(&ann).load().unwrap())
        .unwrap();
    let cli = RosterAccess::from_store(Arc::clone(&store)).unwrap();
    let stamp = store.roster_stamp().unwrap();

    let forged = RouteSet::sign(
        &identity(0x55),
        9,
        NOW_S,
        strings(&["direct:192.168.1.121:9100"]),
    )
    .unwrap();
    let mut limiter = RouteSetLimiter::new();
    let out = ingest_route_sets(
        &cli,
        host().host_id(),
        vec![forged],
        RoutePolicy::AllSigned,
        &mut limiter,
        T0,
    )
    .unwrap();
    assert!(matches!(
        out[..],
        [IngestOutcome::Ignored {
            reason: IngestIgnored::Rejected(RouteSetIgnored::KeyMismatch),
            ..
        }]
    ));
    assert_eq!(
        store.roster_stamp().unwrap(),
        stamp,
        "an ignored set writes nothing"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let set_mode = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set_mode(0o500);
        let writable = std::fs::write(dir.path().join(".probe"), b"x").is_ok();
        let good = |seq| {
            RouteSet::sign(&host(), seq, NOW_S, strings(&["direct:192.168.1.122:9100"])).unwrap()
        };
        let mut limiter = RouteSetLimiter::new();
        let failed = ingest_route_sets(
            &cli,
            host().host_id(),
            vec![good(5)],
            RoutePolicy::AllSigned,
            &mut limiter,
            T0 + 20 * SEC,
        );
        set_mode(0o700);
        if !writable {
            assert!(failed.is_err(), "the store write fails in a read-only dir");
            let retry = ingest_route_sets(
                &cli,
                host().host_id(),
                vec![good(5)],
                RoutePolicy::AllSigned,
                &mut limiter,
                T0 + 21 * SEC,
            )
            .unwrap();
            assert!(
                matches!(retry[..], [IngestOutcome::Applied { seq: 5, .. }]),
                "a failed write gives the rate-limit window back: {retry:?}"
            );
        }
    }
}
