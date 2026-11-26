//! M2M enrolment routes (`spec/pairing-v1.md` Section 7.5): the host-signed route set in the
//! enrolment reply and the operator endpoint fallback are persisted with the host pin, so a
//! client that restarts with only its store connects on Day 2 with no manual route.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use tendril_core::crypto::device_id;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::grants::Grant;
use tendril_core::identity::EndpointIdentity;
use tendril_core::noise::NoiseHfsHandshakeBuilder;
use tendril_core::pairing::{
    EnrollmentPolicy, EnrollmentRoutes, PairOutcome, PairingConfig, PairingManager, PinnedHost,
    RoutePolicy, mint_enrollment_token,
};
use tendril_core::roster::{PeerState, Roster, RouteOrigin, RouteSource};
use tendril_core::routes::RouteSet;
use tendril_core::wire::{HostHello, Intent, PairClaim, Preamble, ResumableFrameReader};
use tendril_runtime::providers::hints::{
    HintDialerConfig, HintDialers, set_peer_routes, stored_route_inputs,
};
use tendril_runtime::{
    ConnectOpts, DEFAULT_PRE_AUTH_TIMEOUT, DirectDialer, DirectListener, EnrollRouteWarning,
    M2mEnrollOptions, M2mEnrollResult, PathDialer, PathListener, PathStream, PrefixedPathStream,
    RosterAccess, RuntimeError, SessionDriver, StateStore, drive_m2m_enroll_initiator_with_routes,
    drive_m2m_enroll_initiator_with_store, drive_pair_responder_with_policy_and_store,
    pairing_path_kind_for_provider, peek_exact, send_tendril_frame,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// An M2M-enabled host that serves pairing and sessions on one loopback listener.
#[derive(Clone)]
struct Host {
    identity: Arc<EndpointIdentity>,
    manager: Arc<Mutex<PairingManager>>,
    roster: Arc<Mutex<Roster>>,
    sessions: Arc<Mutex<Vec<SessionDriver>>>,
}

impl Host {
    fn new(tag: u8) -> Self {
        Self::with_identity(EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([tag; 32]),
            SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
        ))
    }

    fn with_identity(identity: EndpointIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
            manager: Arc::new(Mutex::new(PairingManager::new(PairingConfig::default()))),
            roster: Arc::new(Mutex::new(Roster::new())),
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn id(&self) -> String {
        self.identity.host_id().to_owned()
    }

    /// Records `hints` as the host's announced route state (`spec/pairing-v1.md` 6.11.2).
    fn publish(&self, hints: &[String]) {
        let set = PairingManager::announced_route_set(&self.identity, hints);
        self.roster
            .lock()
            .unwrap()
            .bump_local_routes(&set, now())
            .expect("publish routes");
    }

    fn token(&self, client: &EndpointIdentity, nonce: u8) -> Grant {
        mint_enrollment_token(
            &self.identity,
            self.identity.host_id(),
            Some(&client.device_id()),
            now(),
            900,
            [nonce; 16],
        )
        .expect("token")
    }

    fn pin(&self) -> PinnedHost {
        PinnedHost::with_hash(
            Some(self.id()),
            *self.identity.static_key().public_bytes(),
            self.identity.signing_key().signing_pub_hash(),
            self.identity.rotation_seq(),
        )
    }

    fn burned(&self) -> usize {
        self.roster.lock().unwrap().burned_enrollment_nonce_count()
    }

    fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    async fn serve(&self) -> u16 {
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .expect("bind");
        let port = listener.local_addr().port();
        let host = self.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = listener.accept().await {
                let host = host.clone();
                tokio::spawn(async move {
                    let Ok(prefix) = peek_exact(stream.as_mut(), 6).await else {
                        return;
                    };
                    if !prefix.starts_with(b"TND") {
                        return;
                    }
                    let intent = prefix[4];
                    let mut stream: Box<dyn PathStream> =
                        Box::new(PrefixedPathStream::new(stream, prefix));
                    if intent == Intent::Pair as u8 {
                        let kind = pairing_path_kind_for_provider(stream.provider_id());
                        let _ = drive_pair_responder_with_policy_and_store(
                            stream.as_mut(),
                            &host.identity,
                            &host.manager,
                            &host.roster,
                            None,
                            kind,
                            now(),
                            EnrollmentPolicy::enabled_default(),
                            None,
                            None,
                            DEFAULT_PRE_AUTH_TIMEOUT,
                        )
                        .await;
                    } else if let Ok(session) = SessionDriver::accept_locked(
                        stream,
                        &host.identity,
                        &host.roster,
                        now(),
                        None,
                        None,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                    {
                        host.sessions.lock().unwrap().push(session);
                    }
                });
            }
        });
        port
    }
}

fn direct(port: u16) -> String {
    format!("direct:127.0.0.1:{port}")
}

async fn dial(port: u16) -> Box<dyn PathStream> {
    DirectDialer::new()
        .dial(&format!("127.0.0.1:{port}"))
        .await
        .expect("dial")
}

fn connect_opts() -> ConnectOpts {
    ConnectOpts::new(Arc::new(HintDialers::new(HintDialerConfig::default())))
}

/// Opens the store again as a restarted process would, connects to `host` on Day 2 from the
/// stored routes alone, and returns the winning route.
async fn restart_and_connect(dir: &std::path::Path, host: &Host) -> String {
    let store = Arc::new(StateStore::open_or_create(dir).expect("reopen store"));
    let identity = Arc::new(store.load_identity().expect("identity"));
    let access = RosterAccess::from_store(Arc::clone(&store)).expect("roster access");
    let res =
        SessionDriver::connect_with_policy_and_store(identity, &host.id(), &access, connect_opts())
            .await
            .expect("Day-2 connect over the enrolment routes");
    for _ in 0..50 {
        if host.session_count() == 1 {
            return res.route.addr;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("host never accepted the Day-2 session");
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_with_routes_persists_the_signed_route_set_and_day2_connects_after_restart() {
    let host = Host::new(0x71);
    let port = host.serve().await;
    host.publish(&[direct(port)]);
    let dir = tempfile::tempdir().expect("tempdir");

    let res = enrol_with_routes(dir.path(), &host, port, M2mEnrollOptions::default()).await;
    assert!(matches!(res.route_set, Some(EnrollmentRoutes::Verified(_))));
    let roster = load(dir.path());
    let entry = roster
        .get(&host.id())
        .expect("host pinned by the enrolment");
    assert_eq!(entry.state, PeerState::Active);
    assert_eq!(
        entry.routes_from(RouteSource::Signed).collect::<Vec<_>>(),
        vec![direct(port).as_str()]
    );
    assert_eq!(entry.routes_from(RouteSource::Committed).count(), 0);
    let meta = entry.route_meta.expect("route meta");
    assert_eq!((meta.origin, meta.seq), (RouteOrigin::Session, 1));

    assert_eq!(restart_and_connect(dir.path(), &host).await, direct(port));
}

/// A scripted Wire v1 M2M host on `listener` that records the decrypted `PairClaim` and accepts.
async fn scripted_host(
    identity: EndpointIdentity,
) -> (u16, tokio::sync::oneshot::Receiver<PairClaim>) {
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .expect("bind");
    let port = listener.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        while let Ok(mut stream) = listener.accept().await {
            let Ok(prefix) = peek_exact(stream.as_mut(), 3).await else {
                continue;
            };
            if !prefix.starts_with(b"TND") {
                continue;
            }
            let mut stream: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(stream, prefix));
            let mut reader = ResumableFrameReader::with_preamble();
            let mut buf = vec![0u8; 70_000];
            let preamble = Preamble::v1(Intent::Pair).encode();
            let mut hs = NoiseHfsHandshakeBuilder::new()
                .local_private_key(identity.static_key().secret_bytes())
                .prologue(&preamble)
                .build_responder()
                .unwrap();
            let mut frames = Vec::new();
            let mut preamble_seen = false;
            while frames.len() < 2 {
                let n = stream.recv_chunk(&mut buf).await.unwrap();
                reader.push(&buf[..n]).unwrap();
                if !preamble_seen {
                    preamble_seen = reader.take_preamble().unwrap().is_some();
                    if !preamble_seen {
                        continue;
                    }
                }
                while let Some(f) = reader.next_frame().unwrap() {
                    frames.push(f);
                }
                if frames.len() == 1 {
                    hs.read_message_vec(&frames[0]).unwrap();
                    let hello = serde_json::to_vec(&HostHello {
                        host_id: identity.host_id().to_owned(),
                        proto_version: 1,
                        signing_pub: identity.signing_key().public_key().to_b64url(),
                        rotation: identity.rotation_chain().to_vec(),
                        upgrade: vec![],
                    })
                    .unwrap();
                    let m2 = hs.write_message_vec(&hello).unwrap();
                    send_tendril_frame(stream.as_mut(), &m2).await.unwrap();
                }
            }
            let claim_json = hs.read_message_vec(&frames[1]).unwrap();
            let peer = device_id(hs.get_remote_static().unwrap());
            let mut transport = hs.into_transport_mode().unwrap();
            let reply = serde_json::to_vec(&json!({
                "device_id": peer,
                "status": "active",
                "host_signing_pub": identity.signing_key().public_key().to_b64url(),
            }))
            .unwrap();
            let m4 = transport.write_message_vec(&reply).unwrap();
            send_tendril_frame(stream.as_mut(), &m4).await.unwrap();
            if let Some(tx) = tx.take() {
                let _ = tx.send(serde_json::from_slice(&claim_json).unwrap());
            }
        }
    });
    (port, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_with_store_requests_no_routes_and_stores_none() {
    let host = Host::new(0x70);
    let (port, claim) = scripted_host((*host.identity).clone()).await;
    host.publish(&[direct(port)]);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let me = store.load_or_generate_identity(None).expect("identity");
    let mut stream = dial(port).await;
    let res = drive_m2m_enroll_initiator_with_store(
        stream.as_mut(),
        &me,
        "runner".into(),
        "machine".into(),
        host.token(&me, 0x01),
        host.pin(),
        &store,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    .expect("enrol");
    let _ = stream.close().await;
    assert!(matches!(res.outcome, PairOutcome::InitiatorEnrolled { .. }));
    let claim = claim.await.expect("claim");
    assert_eq!(claim.route_seq, None, "no route set is requested");
    assert!(claim.enrollment_token.is_some());

    let roster = store.load_roster().expect("roster");
    let entry = roster.get(&host.id()).expect("host pinned");
    assert_eq!(entry.state, PeerState::Active);
    assert!(entry.routes.is_empty());
    assert!(entry.route_meta.is_none());
}

fn rotated_twice(base: &EndpointIdentity) -> EndpointIdentity {
    let mut id = base.clone();
    for tag in [0x91u8, 0x93] {
        id.rotate(
            StaticKeypair::from_scalar([tag; 32]),
            SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
            now(),
        )
        .expect("rotate");
    }
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_pin_is_upgraded_to_the_stored_rotation() {
    let base = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x8A; 32]),
        SigningKeypair::from_seed([0x8B; 32]),
    );
    let current = rotated_twice(&base);
    assert_eq!(current.rotation_seq(), 2);
    let stale_pin = PinnedHost::with_hash(
        Some(base.host_id().to_owned()),
        *base.static_key().public_bytes(),
        base.signing_key().signing_pub_hash(),
        0,
    );
    let seeded = |dir: &std::path::Path| {
        let store = StateStore::open_or_create(dir).expect("store");
        store
            .update_roster(|r| {
                r.insert_pinned_host(
                    current.host_id().to_owned(),
                    "Studio".into(),
                    *current.static_key().public_bytes(),
                    Some(current.signing_key().public_key().clone()),
                    2,
                    Vec::new(),
                )
                .map(|_| ())
                .map_err(Into::into)
            })
            .unwrap();
        let me = store.load_or_generate_identity(None).expect("identity");
        (store, me)
    };

    // Someone still holding the rotated-away seq-0 keys is refused at msg2: no claim, no burn.
    let attacker = Host::with_identity(base.clone());
    let port = attacker.serve().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, me) = seeded(dir.path());
    let before = serde_json::to_value(store.load_roster().unwrap()).unwrap();
    let mut stream = dial(port).await;
    let err = drive_m2m_enroll_initiator_with_routes(
        stream.as_mut(),
        &me,
        "runner".into(),
        "machine".into(),
        attacker.token(&me, 0x06),
        stale_pin.clone(),
        &store,
        M2mEnrollOptions::default(),
    )
    .await
    .expect_err("old keys");
    let _ = stream.close().await;
    assert!(
        matches!(err, RuntimeError::Core(CoreError::HostKeyUnverified)),
        "{err}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(attacker.burned(), 0, "the token never reached a claim");
    assert_eq!(
        serde_json::to_value(store.load_roster().unwrap()).unwrap(),
        before
    );

    // The genuine host at seq 2 still enrols with the stale pin.
    let genuine = Host::with_identity(current.clone());
    let port = genuine.serve().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, me) = seeded(dir.path());
    let mut stream = dial(port).await;
    let res = drive_m2m_enroll_initiator_with_routes(
        stream.as_mut(),
        &me,
        "runner".into(),
        "machine".into(),
        genuine.token(&me, 0x07),
        stale_pin,
        &store,
        M2mEnrollOptions::default(),
    )
    .await
    .expect("genuine host");
    let _ = stream.close().await;
    assert!(matches!(
        res.drive.outcome,
        PairOutcome::InitiatorEnrolled { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_id_pinned_with_other_keys_aborts_before_msg3() {
    let identity = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x8C; 32]),
        SigningKeypair::from_seed([0x8D; 32]),
    )
    .with_host_id("studio");
    let other = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x8E; 32]),
        SigningKeypair::from_seed([0x8F; 32]),
    );
    let host = Host::with_identity(identity.clone());
    let port = host.serve().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let me = store.load_or_generate_identity(None).expect("identity");
    store
        .update_roster(|r| {
            r.insert_pinned_host(
                "studio".into(),
                "Studio".into(),
                *other.static_key().public_bytes(),
                Some(other.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .map(|_| ())
            .map_err(Into::into)
        })
        .unwrap();
    let before = serde_json::to_value(store.load_roster().unwrap()).unwrap();
    let unscoped = PinnedHost::with_hash(
        None,
        *identity.static_key().public_bytes(),
        identity.signing_key().signing_pub_hash(),
        0,
    );

    let mut stream = dial(port).await;
    let err = drive_m2m_enroll_initiator_with_routes(
        stream.as_mut(),
        &me,
        "runner".into(),
        "machine".into(),
        host.token(&me, 0x08),
        unscoped,
        &store,
        M2mEnrollOptions::default(),
    )
    .await
    .expect_err("host_id conflict");
    let _ = stream.close().await;
    assert!(
        matches!(err, RuntimeError::Core(CoreError::ProtocolViolation(_))),
        "{err}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(host.burned(), 0, "the token is not spent");
    assert_eq!(
        serde_json::to_value(store.load_roster().unwrap()).unwrap(),
        before
    );
}

async fn enrol_with_routes(
    dir: &std::path::Path,
    host: &Host,
    port: u16,
    opts: M2mEnrollOptions,
) -> M2mEnrollResult {
    enrol_nonce(dir, host, port, opts, 0x02).await
}

async fn enrol_nonce(
    dir: &std::path::Path,
    host: &Host,
    port: u16,
    opts: M2mEnrollOptions,
    nonce: u8,
) -> M2mEnrollResult {
    let store = StateStore::open_or_create(dir).expect("store");
    let me = store.load_or_generate_identity(None).expect("identity");
    let mut stream = dial(port).await;
    let res = drive_m2m_enroll_initiator_with_routes(
        stream.as_mut(),
        &me,
        "runner".into(),
        "machine".into(),
        host.token(&me, nonce),
        host.pin(),
        &store,
        opts,
    )
    .await
    .expect("enrol");
    let _ = stream.close().await;
    assert!(matches!(
        res.drive.outcome,
        PairOutcome::InitiatorEnrolled { .. }
    ));
    assert_eq!(
        store
            .load_roster()
            .unwrap()
            .get(&host.id())
            .expect("host pinned")
            .state,
        PeerState::Active
    );
    res
}

fn committed_routes(dir: &std::path::Path, host: &Host) -> Vec<String> {
    let roster = StateStore::open_or_create(dir)
        .unwrap()
        .load_roster()
        .unwrap();
    let entry = roster.get(&host.id()).unwrap();
    assert_eq!(entry.routes_from(RouteSource::Signed).count(), 0);
    entry
        .routes_from(RouteSource::Committed)
        .map(str::to_owned)
        .collect()
}

fn with_endpoint(endpoint: String) -> M2mEnrollOptions {
    M2mEnrollOptions {
        operator_endpoint: Some(endpoint),
        ..M2mEnrollOptions::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn host_without_route_state_falls_back_to_the_operator_endpoint() {
    let host = Host::new(0x72);
    let port = host.serve().await;
    let dir = tempfile::tempdir().expect("tempdir");

    let res = enrol_with_routes(
        dir.path(),
        &host,
        port,
        with_endpoint(format!("127.0.0.1:{port}")),
    )
    .await;
    assert_eq!(res.route_set, Some(EnrollmentRoutes::Absent));
    assert!(res.route_warnings.is_empty(), "{:?}", res.route_warnings);
    assert_eq!(res.routes_persisted.len(), 1);
    assert_eq!(committed_routes(dir.path(), &host), vec![direct(port)]);

    assert_eq!(restart_and_connect(dir.path(), &host).await, direct(port));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_signed_set_still_stores_the_operator_endpoint() {
    let host = Host::new(0x73);
    let port = host.serve().await;
    host.publish(&[]);
    let dir = tempfile::tempdir().expect("tempdir");

    let res = enrol_with_routes(
        dir.path(),
        &host,
        port,
        with_endpoint(format!("127.0.0.1:{port}")),
    )
    .await;
    assert!(matches!(
        res.route_set,
        Some(EnrollmentRoutes::Verified(ref set)) if set.routes.is_empty()
    ));
    assert_eq!(committed_routes(dir.path(), &host), vec![direct(port)]);
    let roster = StateStore::open_or_create(dir.path())
        .unwrap()
        .load_roster()
        .unwrap();
    let meta = roster.get(&host.id()).unwrap().route_meta.expect("meta");
    assert_eq!((meta.seq, meta.origin), (1, RouteOrigin::Session));

    assert_eq!(restart_and_connect(dir.path(), &host).await, direct(port));
}

fn load(dir: &std::path::Path) -> Roster {
    StateStore::open_or_create(dir)
        .unwrap()
        .load_roster()
        .unwrap()
}

async fn dead_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_set_and_operator_endpoint_are_both_stored_signed_first() {
    let host = Host::new(0x74);
    let port = host.serve().await;
    // The host only advertises a route this client cannot reach (a LAN-only set, from a
    // client that enrolled through a remote endpoint).
    let unreachable = direct(dead_port().await);
    host.publish(std::slice::from_ref(&unreachable));
    let dir = tempfile::tempdir().expect("tempdir");

    let res = enrol_with_routes(
        dir.path(),
        &host,
        port,
        with_endpoint(format!("127.0.0.1:{port}")),
    )
    .await;
    assert!(matches!(res.route_set, Some(EnrollmentRoutes::Verified(_))));
    assert_eq!(
        res.routes_persisted
            .iter()
            .map(|r| r.source)
            .collect::<Vec<_>>(),
        vec![RouteSource::Signed, RouteSource::Committed]
    );
    let ranked = |roster: &Roster| {
        stored_route_inputs(roster.get(&host.id()).unwrap())
            .into_iter()
            .map(|i| i.hint)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ranked(&load(dir.path())),
        vec![unreachable.clone(), direct(port)]
    );

    assert_eq!(restart_and_connect(dir.path(), &host).await, direct(port));

    // A later announcement still replaces the signed routes, keeps the committed endpoint,
    // and the signed routes stay ranked first.
    let next = direct(dead_port().await);
    let set = RouteSet::sign(&host.identity, 2, now(), vec![next.clone()]).unwrap();
    let store = StateStore::open_or_create(dir.path()).unwrap();
    store
        .update_roster(|r| {
            r.apply_route_announcement(&host.id(), &set, now())
                .map_err(Into::into)
        })
        .unwrap();
    assert_eq!(ranked(&load(dir.path())), vec![next, direct(port)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn route_policies_committed_only_and_none() {
    for policy in [RoutePolicy::CommittedOnly, RoutePolicy::None] {
        let host = Host::new(0x75);
        let port = host.serve().await;
        host.publish(&[direct(port)]);
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = M2mEnrollOptions {
            policy,
            ..with_endpoint(format!("127.0.0.1:{port}"))
        };
        let res = enrol_with_routes(dir.path(), &host, port, opts).await;
        assert_eq!(res.route_set, None, "{policy:?}");
        let roster = load(dir.path());
        let entry = roster.get(&host.id()).unwrap();
        assert!(entry.route_meta.is_none());
        if policy == RoutePolicy::None {
            assert!(entry.routes.is_empty(), "nothing is stored under none");
            assert!(res.routes_persisted.is_empty());
        } else {
            assert_eq!(committed_routes(dir.path(), &host), vec![direct(port)]);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn re_enrolment_replaces_the_committed_endpoint() {
    let host = Host::new(0x77);
    let first = host.serve().await;
    let second = host.serve().await;
    host.publish(&[direct(first)]);
    let dir = tempfile::tempdir().expect("tempdir");

    enrol_with_routes(
        dir.path(),
        &host,
        first,
        with_endpoint(format!("127.0.0.1:{first}")),
    )
    .await;
    let store = StateStore::open_or_create(dir.path()).unwrap();
    store
        .update_roster(|r| {
            let id = host.id();
            let entry = r.get(&id).unwrap().clone();
            r.insert_pinned_host(
                id,
                "Studio".into(),
                entry.static_pub,
                entry.signing_pub,
                entry.rotation_seq,
                Vec::new(),
            )
            .map(|_| ())
            .map_err(Into::into)
        })
        .unwrap();

    // The public address changed: the operator enrols again through the new one.
    let res = enrol_nonce(
        dir.path(),
        &host,
        second,
        with_endpoint(format!("127.0.0.1:{second}")),
        0x03,
    )
    .await;
    assert_eq!(
        res.route_set,
        Some(EnrollmentRoutes::Absent),
        "route_seq 1 is current"
    );
    let roster = load(dir.path());
    let entry = roster.get(&host.id()).unwrap();
    assert_eq!(entry.name, "Studio", "re-enrolment keeps the display name");
    assert_eq!(
        entry
            .routes_from(RouteSource::Committed)
            .collect::<Vec<_>>(),
        vec![direct(second).as_str()]
    );
    assert_eq!(
        entry.routes_from(RouteSource::Signed).collect::<Vec<_>>(),
        vec![direct(first).as_str()]
    );
    assert_eq!(entry.route_meta.map(|m| m.seq), Some(1));

    // An explicit operator route update replaces it too.
    store
        .update_roster(|r| {
            set_peer_routes(r, &host.id(), &[format!("127.0.0.1:{first}")]).map(|_| ())
        })
        .unwrap();
    let roster = load(dir.path());
    let entry = roster.get(&host.id()).unwrap();
    assert_eq!(entry.routes_from(RouteSource::Committed).count(), 0);
    assert_eq!(
        entry.routes_from(RouteSource::Operator).collect::<Vec<_>>(),
        vec![direct(first).as_str()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_pin_conflict_fails_before_the_token_is_spent() {
    let host = Host::new(0x78);
    let port = host.serve().await;
    let other = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x79; 32]),
        SigningKeypair::from_seed([0x7A; 32]),
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let me = store.load_or_generate_identity(None).expect("identity");
    store
        .update_roster(|r| {
            r.insert_pinned_host(
                host.id(),
                "Studio".into(),
                *other.static_key().public_bytes(),
                Some(other.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .map(|_| ())
            .map_err(Into::into)
        })
        .unwrap();
    let before = serde_json::to_value(store.load_roster().unwrap()).unwrap();

    let mut stream = dial(port).await;
    let err = drive_m2m_enroll_initiator_with_routes(
        stream.as_mut(),
        &me,
        "runner".into(),
        "machine".into(),
        host.token(&me, 0x04),
        host.pin(),
        &store,
        with_endpoint(format!("127.0.0.1:{port}")),
    )
    .await
    .expect_err("pin conflict");
    let _ = stream.close().await;
    assert!(
        matches!(err, RuntimeError::Core(CoreError::ProtocolViolation(_))),
        "{err}"
    );
    assert_eq!(
        serde_json::to_value(store.load_roster().unwrap()).unwrap(),
        before
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let host_roster = host.roster.lock().unwrap();
    assert_eq!(
        host_roster.burned_enrollment_nonce_count(),
        0,
        "token not spent"
    );
    assert!(host_roster.get(&me.device_id()).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unstorable_operator_endpoint_is_a_warning_not_a_failure() {
    let host = Host::new(0x76);
    let port = host.serve().await;
    let dir = tempfile::tempdir().expect("tempdir");

    let res = enrol_with_routes(
        dir.path(),
        &host,
        port,
        with_endpoint("/run/tendril/host.sock".into()),
    )
    .await;
    assert!(res.routes_persisted.is_empty());
    assert!(matches!(
        res.route_warnings.as_slice(),
        [EnrollRouteWarning::OperatorEndpointRefused(_)]
    ));
    let roster = StateStore::open_or_create(dir.path())
        .unwrap()
        .load_roster()
        .unwrap();
    assert!(roster.get(&host.id()).unwrap().routes.is_empty());
}
