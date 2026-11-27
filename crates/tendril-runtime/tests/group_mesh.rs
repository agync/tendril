//! Hermetic 4-node group mesh over loopback TCP: A is the root, B, C, and D pair only with A.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationListUnsigned, sign_crl};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSeq, GroupSigner, V2GroupSecrets,
    add_member, create_group, decode_group_rendezvous_frame, derive_pair_bootstrap,
    group_id_from_root, remove_member, renew_manifest,
};
use tendril_core::identity::EndpointIdentity;
use tendril_core::policy::ProviderId;
use tendril_core::roster::{Roster, V2PeerSecrets};
use tendril_core::v2::{MAX_PADDED_PAYLOAD_LEN, PaddingPolicy};
use tendril_runtime::MemoryWakeProvider;
use tendril_runtime::{
    DirectDialer, DirectListener, GroupEvent, GroupFrameKind, GroupHub, GroupPool, GroupPoolConfig,
    InboundSession, MAX_LOCAL_GROUPS, PathDialer, PathListener, PathReader, PathStream, PathWriter,
    PreAuthConfig, RuntimeError, SessionDriver, SessionEvent, StateStore, V2ResponderState,
    V2SessionDriver, WakeAdapterKind, WakeProvider, WakeSecret, WakeTarget, group_forget,
    handle_session_group_frame, ingest_pushed_manifest, ingest_pushed_rendezvous,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Node {
    _dir: TempDir,
    store: StateStore,
    identity: Arc<EndpointIdentity>,
    listener: Option<DirectListener>,
    addr: SocketAddr,
    hint: String,
}

impl Node {
    async fn new(n: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_or_create(dir.path()).unwrap();
        let identity = Arc::new(EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x61 + n; 32]),
            SigningKeypair::from_seed([0x71 + n; 32]),
        ));
        let listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let addr = listener.local_addr();
        Self {
            _dir: dir,
            store,
            identity,
            listener: Some(listener),
            addr,
            hint: format!("direct:{addr}"),
        }
    }

    fn id(&self) -> String {
        self.identity.device_id()
    }

    fn member(&self, name: &str, gid: &str, send: bool) -> GroupMember {
        let mut caps = vec![format!("group.recv:{gid}")];
        if send {
            caps.push(format!("group.send:{gid}"));
        }
        GroupMember::new(
            self.identity.static_key().public_bytes(),
            name,
            self.identity.signing_key().public_key(),
            vec![self.hint.clone()],
            caps,
        )
    }
}

fn ids<const N: usize>(list: [String; N]) -> Vec<String> {
    let mut v = list.to_vec();
    v.sort();
    v
}

fn pair(a: &Node, x: &Node, secrets: Option<&V2PeerSecrets>) {
    a.store
        .update_roster(|r| {
            r.record_pending_pair(
                *x.identity.static_key().public_bytes(),
                Some(x.identity.signing_key().public_key().clone()),
                "peer".into(),
                "peer".into(),
                "1111".into(),
            )?;
            r.confirm_peer(&x.id(), Some("1111"))?;
            if let Some(s) = secrets {
                r.upgrade_peer_to_v2(&x.id(), s.clone())?;
            }
            Ok(())
        })
        .unwrap();
    x.store
        .update_roster(|r| {
            r.insert_pinned_host(
                a.id(),
                "root".into(),
                *a.identity.static_key().public_bytes(),
                Some(a.identity.signing_key().public_key().clone()),
                0,
                vec![],
            )?;
            if let Some(s) = secrets {
                r.upgrade_peer_to_v2(&a.id(), s.clone())?;
            }
            Ok(())
        })
        .unwrap();
}

/// Pushes `manifest` and the rendezvous key from the root to `x` over a plain paired session.
async fn push_plain(
    a: &Node,
    x: &Node,
    wire: u8,
    manifest: &GroupManifest,
    secrets: &V2GroupSecrets,
) {
    let listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let x_store = x.store.clone();
    let x_identity = Arc::clone(&x.identity);
    let a_id = a.id();
    let x_id = x.id();
    let server = tokio::spawn(async move {
        let mut listener = listener;
        let stream = tendril_runtime::PathListener::accept(&mut listener)
            .await
            .unwrap();
        let mut roster = x_store.load_roster().unwrap();
        let mut got_manifest = false;
        let mut got_key = false;
        if wire == 1 {
            let session = SessionDriver::accept(stream, &x_identity, &mut roster, now(), None)
                .await
                .unwrap()
                .into_concurrent();
            let roster = Mutex::new(roster);
            while !(got_manifest && got_key) {
                match session.next_event_locked_now(&roster).await.unwrap() {
                    Some(SessionEvent::GroupManifestReceived(m)) => {
                        ingest_pushed_manifest(&x_store, &x_id, &a_id, &m).unwrap();
                        got_manifest = true;
                    }
                    Some(SessionEvent::GroupRendezvousReceived(f)) => {
                        ingest_pushed_rendezvous(&x_store, &x_id, &a_id, &f).unwrap();
                        got_key = true;
                    }
                    Some(_) => {}
                    None => panic!("session closed early"),
                }
            }
        } else {
            let state = V2ResponderState::new();
            let session =
                V2SessionDriver::accept(stream, &x_identity, &mut roster, now(), &state, None)
                    .await
                    .unwrap()
                    .into_concurrent();
            let roster = Mutex::new(roster);
            while !(got_manifest && got_key) {
                match session.next_event_locked_now(&roster).await.unwrap() {
                    Some(SessionEvent::GroupManifestReceived(m)) => {
                        ingest_pushed_manifest(&x_store, &x_id, &a_id, &m).unwrap();
                        got_manifest = true;
                    }
                    Some(SessionEvent::GroupRendezvousReceived(f)) => {
                        ingest_pushed_rendezvous(&x_store, &x_id, &a_id, &f).unwrap();
                        got_key = true;
                    }
                    Some(_) => {}
                    None => panic!("session closed early"),
                }
            }
        }
    });
    push_to_addr(a, x, wire, addr, manifest, secrets).await;
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
}

/// Connects as A over a plain paired session to `addr` and sends the manifest and key.
async fn push_to_addr(
    a: &Node,
    x: &Node,
    wire: u8,
    addr: SocketAddr,
    manifest: &GroupManifest,
    secrets: &V2GroupSecrets,
) {
    let stream = DirectDialer::new().dial(&addr.to_string()).await.unwrap();
    let mut roster = a.store.load_roster().unwrap();
    if wire == 1 {
        let mut s = SessionDriver::connect(stream, &a.identity, &x.id(), None, &mut roster, now())
            .await
            .unwrap();
        s.send_group_manifest(manifest).await.unwrap();
        s.send_group_rendezvous(secrets, &manifest.group_id)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    } else {
        let mut s =
            V2SessionDriver::connect(stream, &a.identity, &x.id(), None, &mut roster, now())
                .await
                .unwrap();
        s.send_group_manifest(manifest).await.unwrap();
        s.send_group_rendezvous(secrets, &manifest.group_id)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct StallDialer {
    inner: DirectDialer,
    stalled_endpoint: String,
    armed: Arc<AtomicBool>,
}

#[async_trait]
impl PathDialer for StallDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.inner.dial(endpoint).await?;
        if endpoint == self.stalled_endpoint {
            Ok(Box::new(StallStream {
                inner: stream,
                armed: Arc::clone(&self.armed),
            }))
        } else {
            Ok(stream)
        }
    }
}

struct StallStream {
    inner: Box<dyn PathStream>,
    armed: Arc<AtomicBool>,
}

struct StallWriter {
    inner: Box<dyn PathWriter>,
    armed: Arc<AtomicBool>,
}

#[async_trait]
impl PathWriter for StallWriter {
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if self.armed.load(Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        self.inner.send_chunk(bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }
}

#[async_trait]
impl PathStream for StallStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if self.armed.load(Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let armed = self.armed;
        let (r, w) = self.inner.into_split();
        (r, Box::new(StallWriter { inner: w, armed }))
    }
}

async fn expect_event(
    pool: &GroupPool,
    wait: Duration,
    mut pred: impl FnMut(&GroupEvent) -> bool,
) -> GroupEvent {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool.poll_event(left).await {
            Some(ev) if pred(&ev) => return ev,
            Some(_) => {}
            None => panic!("expected event did not arrive"),
        }
    }
}

async fn no_event(pool: &GroupPool, wait: Duration, mut pred: impl FnMut(&GroupEvent) -> bool) {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool.poll_event(left).await {
            Some(ev) if pred(&ev) => panic!("unexpected event {ev:?}"),
            Some(_) => {}
            None => return,
        }
    }
}

fn pool_for(node: &Node, gid: &str, dialers: Vec<Arc<dyn PathDialer>>) -> GroupPool {
    GroupPool::open(
        node.store.clone(),
        Arc::clone(&node.identity),
        gid,
        GroupPoolConfig::new(dialers),
        None,
    )
    .unwrap()
}

fn direct_dialers() -> Vec<Arc<dyn PathDialer>> {
    vec![Arc::new(DirectDialer::new())]
}

async fn run_mesh(wire: u8) {
    let mut a = Node::new(0).await;
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let mut d = Node::new(3).await;
    let gid = group_id_from_root(a.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());

    let (m1, s1) = create_group(
        a.identity.signing_key(),
        "mesh",
        wire,
        a.member("a", &gid, true),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(a.identity.signing_key());
    let (m2, s2) = add_member(&m1, &signer, b.member("b", &gid, true), &s1, params).unwrap();
    let (m3, s3) = add_member(&m2, &signer, c.member("c", &gid, true), &s2, params).unwrap();
    let (m4, s4) = add_member(&m3, &signer, d.member("d", &gid, false), &s3, params).unwrap();
    assert_eq!(m4.seq, 4);

    a.store
        .update_group_book(|book| {
            book.ingest_group_manifest(&m4, now(), None)?;
            book.install_secrets(&gid, s4.clone())?;
            Ok(())
        })
        .unwrap();

    for (i, x) in [&b, &c, &d].into_iter().enumerate() {
        let secrets = (wire == 2).then(|| {
            V2PeerSecrets::new(
                [0x90 + u8::try_from(i).unwrap(); 32],
                [0xA0 + u8::try_from(i).unwrap(); 32],
            )
        });
        pair(&a, x, secrets.as_ref());
        push_plain(&a, x, wire, &m4, &s4).await;
        assert_eq!(
            x.store
                .load_group_book()
                .unwrap()
                .manifest(&gid)
                .unwrap()
                .seq,
            4
        );
        assert_eq!(x.store.load_group_book().unwrap().secrets(&gid), Some(&s4));
    }
    let groups_file = b.store.groups_path();
    assert!(groups_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&groups_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // A goes offline: it never serves, and its manifest endpoint refuses connections.
    drop(a.listener.take());

    let stall = Arc::new(AtomicBool::new(false));
    let b_dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(StallDialer {
        inner: DirectDialer::new(),
        stalled_endpoint: d.addr.to_string(),
        armed: Arc::clone(&stall),
    })];
    let wake = Arc::new(MemoryWakeProvider::new());
    let wake_secret = WakeSecret::from_bytes([0x5A; 32]);
    let pool_b = GroupPool::open(
        b.store.clone(),
        Arc::clone(&b.identity),
        &gid,
        GroupPoolConfig::new(b_dialers).with_wake_target(
            a.id(),
            WakeTarget::new(WakeAdapterKind::Webhook, "https://hook.example/wake").unwrap(),
            wake_secret.clone(),
        ),
        Some(Arc::clone(&wake) as Arc<dyn WakeProvider>),
    )
    .unwrap();
    let pool_c = pool_for(&c, &gid, direct_dialers());
    let pool_d = pool_for(&d, &gid, direct_dialers());
    pool_b.serve(Box::new(b.listener.take().unwrap()));
    pool_c.serve(Box::new(c.listener.take().unwrap()));
    pool_d.serve(Box::new(d.listener.take().unwrap()));

    // B broadcasts: C and D are dialed lazily from the manifest alone; A is offline.
    let report = pool_b.broadcast(None, b"hello-from-b").await.unwrap();
    assert_eq!(report.delivered, ids([c.id(), d.id()]));
    assert_eq!(report.offline, ids([a.id()]));
    assert!(report.failed.is_empty(), "{report:?}");
    for (pool, label) in [(&pool_c, "c"), (&pool_d, "d")] {
        let ev = expect_event(pool, Duration::from_secs(5), |e| {
            matches!(e, GroupEvent::AppData { .. })
        })
        .await;
        assert_eq!(
            ev,
            GroupEvent::AppData {
                sender_device_id: b.id(),
                payload: b"hello-from-b".to_vec()
            },
            "{label}"
        );
    }
    assert_eq!(pool_b.connected_peers(), ids([c.id(), d.id()]));
    let recorded = wake.recorded();
    assert_eq!(
        recorded.len(),
        1,
        "only the offline peer with a wake target is nudged"
    );
    assert_eq!(
        recorded[0].tag,
        wake_secret.derive_tag(recorded[0].now_unix_secs)
    );

    // C reaches B and D, and D (recv-only) cannot be a broadcast target for send-only caps.
    let report = pool_c.broadcast(None, b"hello-from-c").await.unwrap();
    assert_eq!(report.delivered, ids([b.id(), d.id()]));
    assert_eq!(report.offline, ids([a.id()]));
    expect_event(&pool_b, Duration::from_secs(5), |e| {
        matches!(e, GroupEvent::AppData { sender_device_id, .. } if *sender_device_id == c.id())
    })
    .await;

    // Siblings never enter the persisted trust roster; v2 pairwise secrets are group scoped
    // and both ends of a first dial hold the same exported secrets.
    for (x, others) in [(&b, [&c, &d]), (&c, [&b, &d])] {
        let roster = x.store.load_roster().unwrap();
        for o in others {
            assert!(roster.get(&o.id()).is_none(), "sibling leaked into roster");
        }
    }
    let pw_b = b.store.load_group_book().unwrap();
    let pw_c = c.store.load_group_book().unwrap();
    if wire == 2 {
        let eb = pw_b.pairwise_secrets(&gid, &c.id()).expect("b stored c");
        let ec = pw_c.pairwise_secrets(&gid, &b.id()).expect("c stored b");
        assert_eq!(eb, ec);
        let boot = derive_pair_bootstrap(s4.group_rendezvous_key(), s4.seq(), &b.id(), &c.id());
        assert_ne!(*eb.reconnect_secret(), *boot);
    } else {
        assert!(pw_b.pairwise_secrets(&gid, &c.id()).is_none());
    }

    // Reconnect: v2 now uses only the pairwise secrets.
    pool_b.disconnect_all();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let report = pool_b.broadcast(None, b"again").await.unwrap();
    assert_eq!(report.delivered, ids([c.id(), d.id()]));
    expect_event(
        &pool_c,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"again"),
    )
    .await;

    // Unauthorized AppData: D holds recv only. Sending under its recv cap is audited, not surfaced.
    let recv_cap = format!("group.recv:{gid}");
    let report = pool_d
        .broadcast(Some(&recv_cap), b"not-allowed")
        .await
        .unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    let ev = expect_event(&pool_b, Duration::from_secs(5), |e| {
        matches!(e, GroupEvent::Audit(_))
    })
    .await;
    let GroupEvent::Audit(audit) = ev else {
        unreachable!()
    };
    assert!(!audit.allow);
    assert_eq!(audit.subject, d.id());
    assert!(matches!(
        pool_d.broadcast(None, b"x").await,
        Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
    ));
    no_event(&pool_b, Duration::from_millis(300), |e| {
        matches!(e, GroupEvent::AppData { sender_device_id, .. } if *sender_device_id == d.id())
    })
    .await;

    // Payload bounds.
    assert!(matches!(
        pool_b
            .broadcast(None, &vec![0u8; MAX_PADDED_PAYLOAD_LEN + 1])
            .await,
        Err(RuntimeError::FrameTooLarge { .. })
    ));
    assert!(
        pool_b
            .broadcast(None, &vec![7u8; MAX_PADDED_PAYLOAD_LEN])
            .await
            .unwrap()
            .delivered
            .contains(&c.id())
    );

    // Slow-peer isolation: D stops reading, so B's write to D is held up to the 1 s bound while
    // C has already received.
    stall.store(true, Ordering::Release);
    let started = Instant::now();
    let held = pool_b.clone();
    let task = tokio::spawn(async move { held.broadcast(None, b"stall-test").await });
    expect_event(
        &pool_c,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"stall-test"),
    )
    .await;
    assert!(
        !task.is_finished(),
        "the write to D must still be held when C received"
    );
    let report = task.await.unwrap().unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(2500), "{elapsed:?}");
    assert!(report.delivered.contains(&c.id()), "{report:?}");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(report.failed[0].0, d.id());
    assert!(!pool_b.connected_peers().contains(&d.id()));
    stall.store(false, Ordering::Release);

    // Re-establish B-D and C-D, then the root revokes D at seq 5.
    let report = pool_b.broadcast(None, b"back").await.unwrap();
    assert!(report.delivered.contains(&d.id()), "{report:?}");
    assert!(pool_c.connected_peers().contains(&d.id()));

    let (m5, s5) = remove_member(&m4, &signer, &d.id(), &s4, params).unwrap();
    assert_eq!(m5.seq, 5);
    assert_eq!(m5.revoked_members, vec![d.id()]);
    // A is briefly online only toward B, over an ordinary paired session; B's pool picks the
    // stored revocation up and sweeps D.
    push_plain(&a, &b, wire, &m5, &s5).await;
    expect_event(
        &pool_b,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::MemberRevoked { device_id } if *device_id == d.id()),
    )
    .await;
    assert!(!pool_b.connected_peers().contains(&d.id()));
    assert_eq!(pool_b.manifest().unwrap().seq, 5);
    assert!(pool_b.authorize_peer(&d.id(), &recv_cap).is_err());
    pool_b.authorize_peer(&c.id(), &recv_cap).unwrap();
    assert!(
        b.store
            .load_group_book()
            .unwrap()
            .pairwise_secrets(&gid, &d.id())
            .is_none()
    );
    assert_eq!(
        c.store
            .load_group_book()
            .unwrap()
            .manifest(&gid)
            .unwrap()
            .seq,
        4
    );

    // B gossips seq 5 to C when it next establishes a session; C drops D immediately.
    pool_b.disconnect_all();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let report = pool_b.broadcast(None, b"post-revoke").await.unwrap();
    assert_eq!(report.delivered, ids([c.id()]));
    assert_eq!(report.offline, ids([a.id()]));
    expect_event(
        &pool_c,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::MemberRevoked { device_id } if *device_id == d.id()),
    )
    .await;
    assert_eq!(pool_c.manifest().unwrap().seq, 5);
    assert!(!pool_c.connected_peers().contains(&d.id()));
    assert!(pool_c.authorize_peer(&d.id(), &recv_cap).is_err());

    // D's fresh handshake is driven straight into C's accept path and rejected by the responder.
    let d_book = d.store.load_group_book().unwrap();
    let secret = d_book
        .pairwise_secrets(&gid, &c.id())
        .map(|s| *s.reconnect_secret())
        .unwrap_or_else(|| *derive_pair_bootstrap(s4.group_rendezvous_key(), 4, &c.id(), &d.id()));
    let refused = drive_into_accept(&d, &c, &gid, 4, wire, secret, &pool_c).await;
    assert!(refused.is_err(), "revoked D must be refused by C");
    no_event(&pool_c, Duration::from_millis(300), |e| {
        matches!(e, GroupEvent::AppData { sender_device_id, .. } if *sender_device_id == d.id())
    })
    .await;
    assert!(!pool_c.connected_peers().contains(&d.id()));

    pool_b.close();
    pool_c.close();
    pool_d.close();
    assert!(matches!(
        pool_b.broadcast(None, b"x").await,
        Err(RuntimeError::Closed)
    ));
}

/// Pins `target` as `node` would from the manifest (static key and signing hash only).
fn sibling_roster(target: &Node, wire: u8, secret: [u8; 32]) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            target.id(),
            "sibling".into(),
            *target.identity.static_key().public_bytes(),
            None,
            0,
            vec![],
        )
        .unwrap();
    roster
        .pin_signing_hash(
            &target.id(),
            target.identity.signing_key().public_key().sha256_hash(),
        )
        .unwrap();
    if wire == 2 {
        roster
            .upgrade_peer_to_v2(&target.id(), V2PeerSecrets::new(secret, [0; 32]))
            .unwrap();
    }
    roster
}

/// Runs one raw sibling handshake from `from` into `pool.accept` and returns the pool verdict.
async fn drive_into_accept(
    from: &Node,
    to: &Node,
    gid: &str,
    seq: u64,
    wire: u8,
    secret: [u8; 32],
    pool: &GroupPool,
) -> Result<String, RuntimeError> {
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let identity = Arc::clone(&from.identity);
    let target = to.id();
    let roster = Mutex::new(sibling_roster(to, wire, secret));
    let groups = vec![GroupSeq {
        group_id: gid.to_owned(),
        seq,
    }];
    let dial = tokio::spawn(async move {
        let stream = DirectDialer::new().dial(&addr.to_string()).await.unwrap();
        if wire == 2 {
            V2SessionDriver::connect_group_member(
                stream,
                &identity,
                &target,
                secret,
                PaddingPolicy::v2_default(),
                &roster,
                groups,
                now(),
            )
            .await
            .map(|_| ())
        } else {
            SessionDriver::connect_group_member(stream, &identity, &target, &roster, groups, now())
                .await
                .map(|_| ())
        }
    });
    let stream = listener.accept().await.unwrap();
    let verdict = pool.accept(stream).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), dial).await;
    verdict
}

#[tokio::test]
async fn four_node_mesh_wire_v1_survives_root_offline_and_revocation() {
    Box::pin(run_mesh(1)).await;
}

#[tokio::test]
async fn four_node_mesh_wire_v2_bootstraps_then_upgrades_to_pairwise_secrets() {
    Box::pin(run_mesh(2)).await;
}

#[tokio::test]
async fn member_count_is_capped_at_32() {
    let root = Node::new(0).await;
    let gid = group_id_from_root(root.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let (mut manifest, mut secrets) = create_group(
        root.identity.signing_key(),
        "big",
        1,
        root.member("root", &gid, true),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(root.identity.signing_key());
    for i in 1..32u8 {
        let key = SigningKeypair::from_seed([i; 32]);
        let member = GroupMember::new(
            StaticKeypair::from_scalar([0x80 + i; 32]).public_bytes(),
            format!("m{i}"),
            key.public_key(),
            vec![format!("direct:127.0.0.1:{}", 4000 + u16::from(i))],
            vec![format!("group.recv:{gid}")],
        );
        (manifest, secrets) = add_member(&manifest, &signer, member, &secrets, params).unwrap();
    }
    assert_eq!(manifest.members.len(), 32);
    let key = SigningKeypair::from_seed([0xEE; 32]);
    let extra = GroupMember::new(
        StaticKeypair::from_scalar([0xEE; 32]).public_bytes(),
        "overflow",
        key.public_key(),
        vec!["direct:127.0.0.1:4999".to_string()],
        vec![format!("group.recv:{gid}")],
    );
    assert!(add_member(&manifest, &signer, extra, &secrets, params).is_err());
    root.store
        .update_group_book(|book| {
            book.ingest_group_manifest(&manifest, now(), None)
                .map_err(Into::into)
        })
        .unwrap();
}

#[tokio::test]
async fn group_book_store_is_atomic_private_and_rolls_back_on_error() {
    let node = Node::new(0).await;
    let gid = group_id_from_root(node.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let (manifest, secrets) = create_group(
        node.identity.signing_key(),
        "store",
        2,
        node.member("n", &gid, true),
        params,
    )
    .unwrap();
    assert!(node.store.load_group_book().unwrap().group_ids().is_empty());
    assert!(!node.store.groups_path().exists());

    let failed: Result<(), RuntimeError> = node.store.update_group_book(|book| {
        book.ingest_group_manifest(&manifest, now(), None)?;
        Err(RuntimeError::Protocol("abort".to_owned()))
    });
    assert!(failed.is_err());
    assert!(!node.store.groups_path().exists());

    node.store
        .update_group_book(|book| {
            book.ingest_group_manifest(&manifest, now(), None)?;
            book.install_secrets(&gid, secrets.clone())?;
            Ok(())
        })
        .unwrap();
    let loaded = node.store.load_group_book().unwrap();
    assert_eq!(loaded.manifest(&gid), Some(&manifest));
    assert_eq!(loaded.secrets(&gid), Some(&secrets));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(node.store.groups_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::set_permissions(
            node.store.groups_path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(node.store.load_group_book().is_err());
    }
}

/// Builds a group rooted at `nodes[0]` with every node as a member and stores the manifest
/// (and, when `with_key`, the rendezvous key) in each node's book, as an admin push would.
fn seed_group(
    nodes: &[&Node],
    wire: u8,
    with_key: bool,
) -> (String, GroupManifest, V2GroupSecrets) {
    let root = nodes[0];
    let gid = group_id_from_root(root.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let (mut manifest, mut secrets) = create_group(
        root.identity.signing_key(),
        "seeded",
        wire,
        root.member("root", &gid, true),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(root.identity.signing_key());
    for (i, node) in nodes.iter().enumerate().skip(1) {
        (manifest, secrets) = add_member(
            &manifest,
            &signer,
            node.member(&format!("m{i}"), &gid, true),
            &secrets,
            params,
        )
        .unwrap();
    }
    for node in nodes {
        store_manifest(node, &manifest, with_key.then_some(&secrets));
    }
    (gid, manifest, secrets)
}

fn store_manifest(node: &Node, manifest: &GroupManifest, secrets: Option<&V2GroupSecrets>) {
    node.store
        .update_group_book(|book| {
            book.ingest_group_manifest(manifest, now(), None)?;
            if let Some(s) = secrets {
                book.install_secrets(&manifest.group_id, s.clone())?;
            }
            Ok(())
        })
        .unwrap();
}

fn serve_pool(node: &mut Node, gid: &str, config: GroupPoolConfig) -> GroupPool {
    let pool = GroupPool::open(
        node.store.clone(),
        Arc::clone(&node.identity),
        gid,
        config,
        None,
    )
    .unwrap();
    pool.serve(Box::new(node.listener.take().unwrap()));
    pool
}

fn pairwise(node: &Node, gid: &str, peer: &Node) -> Option<V2PeerSecrets> {
    node.store
        .load_group_book()
        .unwrap()
        .pairwise_secrets(gid, &peer.id())
        .cloned()
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < deadline, "condition not reached");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn v2_pairwise_secrets_outlive_the_bootstrap_and_retry_once_with_it() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, m3, s3) = seed_group(&[&a, &b, &c], 2, true);
    let pool_b = serve_pool(&mut b, &gid, GroupPoolConfig::new(direct_dialers()));
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));

    let report = pool_b.broadcast(None, b"first").await.unwrap();
    assert_eq!(report.delivered, ids([c.id()]), "{report:?}");
    let pw1 = pairwise(&b, &gid, &c).expect("b persisted pairwise");
    wait_until(|| pairwise(&c, &gid, &b).as_ref() == Some(&pw1)).await;

    // The bootstrap becomes unavailable on both ends: a renewed manifest without its key.
    let signer = GroupSigner::root(a.identity.signing_key());
    let (m4, s4) = renew_manifest(&m3, &signer, &s3, GroupBuildParams::new(now())).unwrap();
    store_manifest(&b, &m4, None);
    store_manifest(&c, &m4, None);
    for store in [&b.store, &c.store] {
        let book = store.load_group_book().unwrap();
        assert!(book.pair_bootstrap(&gid, &b.id(), &c.id(), now()).is_err());
    }
    wait_until(|| pool_b.manifest().unwrap().seq == 4 && pool_c.manifest().unwrap().seq == 4).await;
    pool_b.disconnect_all();
    pool_c.disconnect_all();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let report = pool_b.broadcast(None, b"pairwise-only").await.unwrap();
    assert_eq!(report.delivered, ids([c.id()]), "{report:?}");
    assert_eq!(pairwise(&b, &gid, &c).as_ref(), Some(&pw1));
    assert_eq!(pairwise(&c, &gid, &b).as_ref(), Some(&pw1));

    // A stale pairwise secret without a bootstrap cannot connect.
    let corrupt = V2PeerSecrets::new([0xC0; 32], [0xC1; 32]);
    b.store
        .update_group_book(|book| {
            book.set_pairwise_secrets(&gid, &c.id(), corrupt.clone())
                .map_err(Into::into)
        })
        .unwrap();
    pool_b.disconnect_all();
    pool_c.disconnect_all();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let report = pool_b.broadcast(None, b"stale").await.unwrap();
    assert!(!report.delivered.contains(&c.id()), "{report:?}");

    // With the current key back, the stale pairwise dial fails once and the bootstrap retry
    // succeeds; its exported secrets overwrite the pairwise entry on both ends.
    for node in [&b, &c] {
        node.store
            .update_group_book(|book| book.install_secrets(&gid, s4.clone()).map_err(Into::into))
            .unwrap();
    }
    wait_until(|| {
        let book = b.store.load_group_book().unwrap();
        book.pair_bootstrap(&gid, &b.id(), &c.id(), now()).is_ok()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let report = pool_b.broadcast(None, b"retried").await.unwrap();
    assert_eq!(report.delivered, ids([c.id()]), "{report:?}");
    expect_event(
        &pool_c,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"retried"),
    )
    .await;
    let pw2 = pairwise(&b, &gid, &c).unwrap();
    wait_until(|| pairwise(&c, &gid, &b).as_ref() == Some(&pw2)).await;
    assert_ne!(pw2, corrupt);
    assert_ne!(pw2, pw1);
    pool_b.close();
    pool_c.close();
}

struct DelayDialer {
    inner: DirectDialer,
    delayed_endpoint: String,
    delay: Duration,
}

#[async_trait]
impl PathDialer for DelayDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        if endpoint == self.delayed_endpoint {
            tokio::time::sleep(self.delay).await;
        }
        self.inner.dial(endpoint).await
    }
}

#[tokio::test]
async fn revocation_cancels_in_flight_writes_and_blocks_slot_publication() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let mut d = Node::new(3).await;
    let (gid, m4, s4) = seed_group(&[&a, &b, &c, &d], 2, true);
    let stall = Arc::new(AtomicBool::new(false));
    let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(StallDialer {
        inner: DirectDialer::new(),
        stalled_endpoint: d.addr.to_string(),
        armed: Arc::clone(&stall),
    })];
    let pool_b = serve_pool(
        &mut b,
        &gid,
        GroupPoolConfig::new(dialers).with_write_timeout(Duration::from_secs(10)),
    );
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));
    let _pool_d = serve_pool(&mut d, &gid, GroupPoolConfig::new(direct_dialers()));

    let report = pool_b.broadcast(None, b"warm").await.unwrap();
    assert_eq!(report.delivered, ids([c.id(), d.id()]), "{report:?}");

    // The write to D is in flight (D stopped reading) when the revocation lands.
    stall.store(true, Ordering::Release);
    let held = pool_b.clone();
    let task = tokio::spawn(async move { held.broadcast(None, b"in-flight").await });
    expect_event(
        &pool_c,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"in-flight"),
    )
    .await;
    let signer = GroupSigner::root(a.identity.signing_key());
    let params = GroupBuildParams::new(now());
    let (m5, _) = remove_member(&m4, &signer, &d.id(), &s4, params).unwrap();
    let revoked_at = Instant::now();
    pool_b.ingest_manifest(&m5).await.unwrap();
    let report = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("revocation must cancel the held write")
        .unwrap()
        .unwrap();
    // Windows takes longer to tear down a stalled socket; the correctness assertions below are
    // unchanged.
    let budget = if cfg!(windows) {
        Duration::from_secs(5)
    } else {
        Duration::from_millis(500)
    };
    assert!(
        revoked_at.elapsed() < budget,
        "{:?} {report:?}",
        revoked_at.elapsed()
    );
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(report.failed[0].0, d.id());
    assert_eq!(
        report.failed[0].1, "session closed",
        "the write must be cancelled, not time out"
    );
    assert!(!pool_b.connected_peers().contains(&d.id()));

    assert!(pairwise(&b, &gid, &d).is_none());
    pool_b.close();
    pool_c.close();
}

#[tokio::test]
async fn in_flight_dial_to_a_revoked_member_never_publishes_a_slot() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, m3, s3) = seed_group(&[&a, &b, &c], 2, true);
    let slow: Vec<Arc<dyn PathDialer>> = vec![Arc::new(DelayDialer {
        inner: DirectDialer::new(),
        delayed_endpoint: c.addr.to_string(),
        delay: Duration::from_millis(600),
    })];
    let pool_b = serve_pool(&mut b, &gid, GroupPoolConfig::new(slow));
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));

    let racing = pool_b.clone();
    let dial = tokio::spawn(async move { racing.broadcast(None, b"race").await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let signer = GroupSigner::root(a.identity.signing_key());
    let (m4, _) = remove_member(&m3, &signer, &c.id(), &s3, GroupBuildParams::new(now())).unwrap();
    store_manifest(&b, &m4, None);
    let report = dial.await.unwrap().unwrap();
    assert!(!report.delivered.contains(&c.id()), "{report:?}");
    assert!(!pool_b.connected_peers().contains(&c.id()));
    assert!(pairwise(&b, &gid, &c).is_none());
    no_event(
        &pool_c,
        Duration::from_millis(300),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"race"),
    )
    .await;
    pool_b.close();
    pool_c.close();
}

#[tokio::test]
async fn crl_revoked_member_is_disconnected_and_its_data_never_delivered() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, _, _) = seed_group(&[&a, &b, &c], 1, true);
    pair(&a, &b, None);
    let pool_b = serve_pool(&mut b, &gid, GroupPoolConfig::new(direct_dialers()));
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));

    let report = pool_c.broadcast(None, b"before").await.unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    expect_event(
        &pool_b,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"before"),
    )
    .await;
    assert!(pool_b.connected_peers().contains(&c.id()));

    let crl = crl_from(&a, &c);
    let a_pub = a.identity.signing_key().public_key().clone();
    b.store
        .update_roster(|r| r.ingest_crl(crl, &a.id(), &a_pub).map_err(Into::into))
        .unwrap();
    wait_until(|| !pool_b.connected_peers().contains(&c.id())).await;
    wait_until(|| !pool_c.connected_peers().contains(&b.id())).await;

    // C completes its own side of the Wire v1 handshake; B refuses C once msg3 names it.
    let _ = pool_c.broadcast(None, b"after").await.unwrap();
    no_event(
        &pool_b,
        Duration::from_millis(300),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"after"),
    )
    .await;
    assert!(!pool_b.connected_peers().contains(&c.id()));
    assert!(
        pool_b
            .authorize_peer(&c.id(), &format!("group.recv:{gid}"))
            .is_err()
    );
    pool_b.close();
    pool_c.close();
}

#[tokio::test]
async fn first_contact_pins_only_from_the_signer_as_an_active_paired_peer() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let c = Node::new(2).await;
    let gid = group_id_from_root(a.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let (m1, s1) = create_group(
        a.identity.signing_key(),
        "fc",
        1,
        a.member("a", &gid, true),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(a.identity.signing_key());
    let (m2, s2) = add_member(&m1, &signer, b.member("b", &gid, true), &s1, params).unwrap();
    let (m3, _) = add_member(&m2, &signer, c.member("c", &gid, true), &s2, params).unwrap();

    // C is an active ordinary peer of B and a member, but not the signer.
    pair(&c, &b, None);
    let refused = ingest_pushed_manifest(&b.store, &b.id(), &c.id(), &m3);
    assert!(
        matches!(
            refused,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{refused:?}"
    );
    assert!(b.store.load_group_book().unwrap().group_ids().is_empty());

    // The signer id is pinned in B's roster, but under a different signing key.
    let forged = Node::new(9).await;
    b.store
        .update_roster(|r| {
            r.insert_pinned_host(
                a.id(),
                "root".into(),
                *a.identity.static_key().public_bytes(),
                Some(forged.identity.signing_key().public_key().clone()),
                0,
                vec![],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(ingest_pushed_manifest(&b.store, &b.id(), &a.id(), &m3).is_err());
    assert!(b.store.load_group_book().unwrap().group_ids().is_empty());

    // An unpaired signer is refused; a paired signer pins the group; a non-member never pins.
    let d = Node::new(3).await;
    assert!(ingest_pushed_manifest(&d.store, &d.id(), &a.id(), &m3).is_err());
    pair(&a, &d, None);
    assert!(ingest_pushed_manifest(&d.store, &d.id(), &a.id(), &m3).is_err());
    assert!(d.store.load_group_book().unwrap().group_ids().is_empty());
    pair(&a, &c, None);
    ingest_pushed_manifest(&c.store, &c.id(), &a.id(), &m3).unwrap();
    assert_eq!(c.store.load_group_book().unwrap().manifest(&gid), Some(&m3));
}

#[tokio::test]
async fn wire_v2_groups_refuse_v1_and_members_without_secrets() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, manifest, secrets) = seed_group(&[&a, &b, &c], 2, false);
    store_manifest(&c, &manifest, None);
    c.store
        .update_group_book(|book| {
            book.install_secrets(&gid, secrets.clone())
                .map_err(Into::into)
        })
        .unwrap();
    let pool_b = serve_pool(&mut b, &gid, GroupPoolConfig::new(direct_dialers()));
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));

    // B holds neither a bootstrap key nor a pairwise secret for C: no usable entry either way.
    let report = pool_b.broadcast(None, b"no-secret").await.unwrap();
    assert!(!report.delivered.contains(&c.id()), "{report:?}");
    let report = pool_c.broadcast(None, b"no-secret").await.unwrap();
    assert!(!report.delivered.contains(&b.id()), "{report:?}");
    assert!(pool_b.connected_peers().is_empty());

    // A Wire v1 sibling handshake into a v2 group's accept path is refused.
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let pool_c2 = pool_c.clone();
    let identity = Arc::clone(&b.identity);
    let roster = Mutex::new(sibling_roster(&c, 1, [0; 32]));
    let c_id = c.id();
    let gid_c = gid.clone();
    let dial = tokio::spawn(async move {
        let stream = DirectDialer::new().dial(&addr.to_string()).await.unwrap();
        let groups = vec![GroupSeq {
            group_id: gid_c,
            seq: 3,
        }];
        let _ =
            SessionDriver::connect_group_member(stream, &identity, &c_id, &roster, groups, now())
                .await;
    });
    let stream = listener.accept().await.unwrap();
    assert!(matches!(
        pool_c2.accept(stream).await,
        Err(RuntimeError::Core(CoreError::VersionDowngrade { .. }))
    ));
    let _ = dial.await;
    pool_b.close();
    pool_c.close();
}

#[tokio::test]
async fn pool_admission_is_bounded_before_any_handshake() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let (gid, _, _) = seed_group(&[&a, &b], 1, true);
    let mut config = GroupPoolConfig::new(direct_dialers());
    config.pre_auth = PreAuthConfig {
        max_half_open: 1,
        ..PreAuthConfig::default()
    };
    let pool =
        GroupPool::open(b.store.clone(), Arc::clone(&b.identity), &gid, config, None).unwrap();
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr().to_string();
    let dial = tokio::spawn(async move {
        let first = DirectDialer::new().dial(&addr).await;
        let second = DirectDialer::new().dial(&addr).await;
        (first, second)
    });
    let silent = listener.accept().await.unwrap();
    let holder = pool.clone();
    let held = tokio::spawn(async move { holder.accept(silent).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stream = listener.accept().await.unwrap();
    let verdict = pool.accept(stream).await;
    assert!(
        matches!(verdict, Err(RuntimeError::RateLimited(_))),
        "{verdict:?}"
    );
    held.abort();
    let _ = dial.await;
}

/// Accepts every stream on `listener` through `hub` and reports how each was routed.
fn spawn_hub_server(
    hub: Arc<GroupHub>,
    mut listener: DirectListener,
) -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let state = Arc::new(V2ResponderState::new());
        loop {
            let Ok(stream) = listener.accept().await else {
                return;
            };
            let hub = Arc::clone(&hub);
            let state = Arc::clone(&state);
            let tx = tx.clone();
            tokio::spawn(async move {
                let routed = match hub.accept(stream, &state, None, None).await {
                    Ok(InboundSession::Group {
                        group_id,
                        peer_device_id,
                    }) => format!("group:{group_id}:{peer_device_id}"),
                    Ok(InboundSession::OrdinaryV1 { session, .. }) => {
                        format!("ordinary:{}", session.peer_device_id().unwrap_or_default())
                    }
                    Ok(InboundSession::OrdinaryV2 { session }) => {
                        format!("ordinary:{}", session.peer_device_id())
                    }
                    Err(err) => format!("refused:{err}"),
                };
                let _ = tx.send(routed);
            });
        }
    });
    rx
}

#[tokio::test]
async fn hub_routes_ordinary_and_group_sessions_and_siblings_stay_out_of_the_roster() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let mut d = Node::new(3).await;
    pair(&a, &b, None);
    let (gid1, _, _) = seed_group(&[&a, &b, &c], 1, true);
    let (gid2, _, _) = seed_group(&[&d, &b], 2, true);

    let hub = Arc::new(GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        GroupPoolConfig::new(direct_dialers()),
        None,
    ));
    assert_eq!(hub.sync().unwrap().len(), 2);
    let mut routed = spawn_hub_server(Arc::clone(&hub), b.listener.take().unwrap());
    let pool_c = serve_pool(&mut c, &gid1, GroupPoolConfig::new(direct_dialers()));
    let pool_d = serve_pool(&mut d, &gid2, GroupPoolConfig::new(direct_dialers()));

    // An ordinary paired peer and two group siblings reach B's one listener concurrently.
    let b_addr = b.addr.to_string();
    let a_store = a.store.clone();
    let a_identity = Arc::clone(&a.identity);
    let b_id = b.id();
    let ordinary = async move {
        let stream = DirectDialer::new().dial(&b_addr).await.unwrap();
        let mut roster = a_store.load_roster().unwrap();
        SessionDriver::connect(stream, &a_identity, &b_id, None, &mut roster, now())
            .await
            .map(|_| ())
    };
    let (ord, rc, rd) = tokio::join!(
        ordinary,
        pool_c.broadcast(None, b"from-c"),
        pool_d.broadcast(None, b"from-d")
    );
    ord.unwrap();
    assert!(rc.unwrap().delivered.contains(&b.id()));
    assert!(rd.unwrap().delivered.contains(&b.id()));
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(
            tokio::time::timeout(Duration::from_secs(5), routed.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    seen.sort();
    let mut expect = vec![
        format!("ordinary:{}", a.id()),
        format!("group:{gid1}:{}", c.id()),
        format!("group:{gid2}:{}", d.id()),
    ];
    expect.sort();
    assert_eq!(seen, expect);
    for (gid, sender, payload) in [(&gid1, c.id(), b"from-c"), (&gid2, d.id(), b"from-d")] {
        let pool = hub.pool(gid).unwrap();
        let ev = expect_event(&pool, Duration::from_secs(5), |e| {
            matches!(e, GroupEvent::AppData { .. })
        })
        .await;
        assert_eq!(
            ev,
            GroupEvent::AppData {
                sender_device_id: sender,
                payload: payload.to_vec()
            }
        );
    }

    // A sibling cannot open an ordinary session to B, and B cannot mint it a grant.
    let stream = DirectDialer::new().dial(&b.addr.to_string()).await.unwrap();
    let mut c_roster = Roster::new();
    c_roster
        .insert_pinned_host(
            b.id(),
            "b".into(),
            *b.identity.static_key().public_bytes(),
            Some(b.identity.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let _ = SessionDriver::connect(stream, &c.identity, &b.id(), None, &mut c_roster, now()).await;
    let verdict = tokio::time::timeout(Duration::from_secs(5), routed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(verdict.starts_with("refused:"), "{verdict}");
    let mut b_roster = b.store.load_roster().unwrap();
    for sibling in [&c, &d] {
        assert!(b_roster.get(&sibling.id()).is_none());
    }
    assert!(
        b_roster
            .mint_grant(
                &b.identity,
                &c.id(),
                vec![format!("group.send:{gid1}")],
                now(),
                now() + 60,
                [7; 16],
            )
            .is_err()
    );
    hub.close();
    pool_c.close();
    pool_d.close();
}

fn crl_from(issuer: &Node, revoked: &Node) -> tendril_core::grants::RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: issuer.id(),
            seq: 1,
            revoked_devices: vec![revoked.id()],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        issuer.identity.signing_key(),
    )
    .unwrap()
}

#[tokio::test]
async fn crl_revocation_closes_links_and_admin_sync_skips_the_member() {
    let mut a = Node::new(0).await;
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, m3, s3) = seed_group(&[&a, &b, &c], 2, true);
    let pool_a = serve_pool(&mut a, &gid, GroupPoolConfig::new(direct_dialers()));
    let pool_b = serve_pool(&mut b, &gid, GroupPoolConfig::new(direct_dialers()));
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));
    let report = pool_a.sync().await.unwrap();
    assert_eq!(report.delivered, ids([b.id(), c.id()]), "{report:?}");

    // C stays in the manifest; only the root CRL revokes it.
    let crl = crl_from(&a, &c);
    let a_pub = a.identity.signing_key().public_key().clone();
    a.store
        .update_roster(|r| r.ingest_crl(crl, &a.id(), &a_pub).map_err(Into::into))
        .unwrap();
    wait_until(|| !pool_a.connected_peers().contains(&c.id())).await;

    let signer = GroupSigner::root(a.identity.signing_key());
    let (m4, s4) = renew_manifest(&m3, &signer, &s3, GroupBuildParams::new(now())).unwrap();
    store_manifest(&a, &m4, Some(&s4));
    let report = pool_a.sync().await.unwrap();
    assert_eq!(report.delivered, ids([b.id()]), "{report:?}");
    wait_until(|| {
        let book = b.store.load_group_book().unwrap();
        book.secrets(&gid).is_some_and(|s| s.seq() == m4.seq)
    })
    .await;
    no_event(
        &pool_c,
        Duration::from_millis(300),
        |e| matches!(e, GroupEvent::ManifestUpdated { seq } if *seq == m4.seq),
    )
    .await;
    let c_book = c.store.load_group_book().unwrap();
    assert_eq!(c_book.manifest(&gid).unwrap().seq, m3.seq);
    assert_eq!(c_book.secrets(&gid).unwrap().seq(), s3.seq());
    assert!(!pool_a.connected_peers().contains(&c.id()));
    pool_a.close();
    pool_b.close();
    pool_c.close();
}

/// Builds a group rooted at `root` with `members`, stored in every node's book with its key.
fn seed_rooted(
    root: &Node,
    members: &[&Node],
    wire: u8,
) -> (String, GroupManifest, V2GroupSecrets) {
    let mut nodes = vec![root];
    nodes.extend_from_slice(members);
    seed_group(&nodes, wire, true)
}

/// Returns the next hub verdict, skipping stray non-Tendril connections that another process
/// on the host may open to a reused loopback port.
async fn next_routed(routed: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
    loop {
        let verdict = tokio::time::timeout(Duration::from_secs(5), routed.recv())
            .await
            .unwrap()
            .unwrap();
        if !verdict.contains("invalid preamble") {
            return verdict;
        }
    }
}

#[tokio::test]
async fn hub_never_diverts_an_ordinary_peer_by_its_gossip_summary() {
    let mut b = Node::new(1).await;
    let c = Node::new(2).await;
    let a = Node::new(0).await;
    let d = Node::new(3).await;
    let e = Node::new(4).await;
    let ordinary = V2PeerSecrets::new([0x5A; 32], [0x5B; 32]);
    pair(&a, &b, None);
    pair(&e, &b, Some(&ordinary));
    let (gid1, _, _) = seed_rooted(&c, &[&b], 1);
    let (gid2, m2, _) = seed_rooted(&d, &[&b, &e], 2);
    let hub = Arc::new(GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        GroupPoolConfig::new(direct_dialers()),
        None,
    ));
    assert_eq!(hub.sync().unwrap().len(), 2);
    let mut routed = spawn_hub_server(Arc::clone(&hub), b.listener.take().unwrap());

    // A is not a member of group 1 but advertises it over Wire v1.
    let stream = DirectDialer::new().dial(&b.addr.to_string()).await.unwrap();
    let roster = Mutex::new(a.store.load_roster().unwrap());
    let groups = vec![GroupSeq {
        group_id: gid1.clone(),
        seq: 2,
    }];
    SessionDriver::connect_group_member(stream, &a.identity, &b.id(), &roster, groups, now())
        .await
        .unwrap();
    let verdict = next_routed(&mut routed).await;
    assert_eq!(verdict, format!("ordinary:{}", a.id()));

    // E is a member of group 2 and advertises it, but rendezvouses with its ordinary secret.
    let stream = DirectDialer::new().dial(&b.addr.to_string()).await.unwrap();
    let roster = Mutex::new(e.store.load_roster().unwrap());
    let groups = vec![GroupSeq {
        group_id: gid2.clone(),
        seq: m2.seq,
    }];
    V2SessionDriver::connect_group_member(
        stream,
        &e.identity,
        &b.id(),
        *ordinary.reconnect_secret(),
        PaddingPolicy::v2_default(),
        &roster,
        groups,
        now(),
    )
    .await
    .unwrap();
    let verdict = next_routed(&mut routed).await;
    assert_eq!(verdict, format!("ordinary:{}", e.id()));
    hub.close();
}

#[tokio::test]
async fn hub_applies_wire_floors_per_group_and_keeps_ordinary_floors() {
    let mut a = Node::new(0).await;
    let mut b = Node::new(1).await;
    let r1 = Node::new(5).await;
    let r2 = Node::new(6).await;
    let mut d = Node::new(3).await;
    // The Wire v2 group sorts first, so a shared roster entry would take its floor.
    let g1 = group_id_from_root(r1.identity.signing_key().public_key());
    let g2 = group_id_from_root(r2.identity.signing_key().public_key());
    let (v2_root, v1_root) = if g1 < g2 { (&r1, &r2) } else { (&r2, &r1) };
    let ordinary = V2PeerSecrets::new([0x6A; 32], [0x6B; 32]);
    pair(&a, &b, Some(&ordinary));
    assert_eq!(
        b.store
            .load_roster()
            .unwrap()
            .get(&a.id())
            .unwrap()
            .min_wire_version,
        2
    );
    let (gid_v2, _, _) = seed_rooted(v2_root, &[&b, &d], 2);
    let (gid_v1, _, _) = seed_rooted(v1_root, &[&b, &d, &a], 1);
    assert!(gid_v2 < gid_v1);
    let hub = Arc::new(GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        GroupPoolConfig::new(direct_dialers()),
        None,
    ));
    assert_eq!(hub.sync().unwrap().len(), 2);
    let mut routed = spawn_hub_server(Arc::clone(&hub), b.listener.take().unwrap());
    let pool_d = serve_pool(&mut d, &gid_v1, GroupPoolConfig::new(direct_dialers()));
    let pool_a = serve_pool(&mut a, &gid_v1, GroupPoolConfig::new(direct_dialers()));

    // D is also a Wire v2 sibling; its Wire v1 session to the Wire v1 group is admitted.
    let report = pool_d.broadcast(None, b"from-d").await.unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    let verdict = next_routed(&mut routed).await;
    assert_eq!(verdict, format!("group:{gid_v1}:{}", d.id()));

    // A's ordinary floor is 2, yet its Wire v1 group session follows the group floor.
    let report = pool_a.broadcast(None, b"from-a").await.unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    let verdict = next_routed(&mut routed).await;
    assert_eq!(verdict, format!("group:{gid_v1}:{}", a.id()));

    // An ordinary Wire v1 session from A is still refused by its persisted floor.
    let mut v1_roster = Roster::new();
    v1_roster
        .insert_pinned_host(
            b.id(),
            "b".into(),
            *b.identity.static_key().public_bytes(),
            Some(b.identity.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let stream = DirectDialer::new().dial(&b.addr.to_string()).await.unwrap();
    let _ = SessionDriver::connect(stream, &a.identity, &b.id(), None, &mut v1_roster, now()).await;
    let verdict = next_routed(&mut routed).await;
    assert!(verdict.starts_with("refused:"), "{verdict}");

    // Its ordinary Wire v2 session is unaffected.
    let stream = DirectDialer::new().dial(&b.addr.to_string()).await.unwrap();
    let mut roster = a.store.load_roster().unwrap();
    V2SessionDriver::connect(stream, &a.identity, &b.id(), None, &mut roster, now())
        .await
        .unwrap();
    let verdict = next_routed(&mut routed).await;
    assert_eq!(verdict, format!("ordinary:{}", a.id()));
    hub.close();
    pool_a.close();
    pool_d.close();
}

#[tokio::test]
async fn local_groups_are_capped_for_pinning_and_opening() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    pair(&a, &b, None);
    let params = GroupBuildParams::new(now());
    let make = |seed: u8| {
        let key = SigningKeypair::from_seed([seed; 32]);
        let gid = group_id_from_root(key.public_key());
        let root = GroupMember::new(
            StaticKeypair::from_scalar([seed; 32]).public_bytes(),
            "root",
            key.public_key(),
            vec!["direct:127.0.0.1:1".to_owned()],
            vec![format!("group.send:{gid}")],
        );
        let (m, s) = create_group(&key, "cap", 1, root, params).unwrap();
        let signer = GroupSigner::root(&key);
        add_member(&m, &signer, b.member("b", &gid, true), &s, params)
            .unwrap()
            .0
    };
    for seed in 0..u8::try_from(MAX_LOCAL_GROUPS).unwrap() {
        store_manifest(&b, &make(0xA0 + seed), None);
    }
    assert_eq!(
        b.store.load_group_book().unwrap().group_ids().len(),
        MAX_LOCAL_GROUPS
    );

    // A paired signer cannot pin a further group.
    let gid_a = group_id_from_root(a.identity.signing_key().public_key());
    let (m1, s1) = create_group(
        a.identity.signing_key(),
        "extra",
        1,
        a.member("a", &gid_a, true),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(a.identity.signing_key());
    let (m2, _) = add_member(&m1, &signer, b.member("b", &gid_a, true), &s1, params).unwrap();
    let refused = ingest_pushed_manifest(&b.store, &b.id(), &a.id(), &m2);
    assert!(
        matches!(
            refused,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{refused:?}"
    );
    assert!(
        b.store
            .load_group_book()
            .unwrap()
            .manifest(&gid_a)
            .is_none()
    );

    // Past the cap (written behind the runtime's back), at most MAX_LOCAL_GROUPS pools open.
    store_manifest(&b, &m2, None);
    let hub = GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        GroupPoolConfig::new(direct_dialers()),
        None,
    );
    assert_eq!(hub.sync().unwrap().len(), MAX_LOCAL_GROUPS);
    let mut all = b.store.load_group_book().unwrap().group_ids();
    all.sort();
    let excluded = all.last().unwrap();
    assert!(hub.pool(excluded).is_none());
    assert!(
        GroupPool::open(
            b.store.clone(),
            Arc::clone(&b.identity),
            excluded,
            GroupPoolConfig::new(direct_dialers()),
            None,
        )
        .is_err()
    );
    hub.close();
}

#[tokio::test]
async fn pool_opened_outside_a_runtime_still_sweeps_crl_revocations_once_served() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, _, _) = seed_group(&[&a, &b, &c], 1, true);
    pair(&a, &b, None);

    let (store, identity) = (b.store.clone(), Arc::clone(&b.identity));
    let gid_b = gid.clone();
    let pool_b = std::thread::spawn(move || {
        GroupPool::open(
            store,
            identity,
            &gid_b,
            GroupPoolConfig::new(direct_dialers()),
            None,
        )
        .unwrap()
    })
    .join()
    .unwrap();
    pool_b.serve(Box::new(b.listener.take().unwrap()));
    let pool_c = serve_pool(&mut c, &gid, GroupPoolConfig::new(direct_dialers()));

    let report = pool_c.broadcast(None, b"hello").await.unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    wait_until(|| pool_b.connected_peers().contains(&c.id())).await;

    let crl = crl_from(&a, &c);
    let a_pub = a.identity.signing_key().public_key().clone();
    b.store
        .update_roster(|r| r.ingest_crl(crl, &a.id(), &a_pub).map_err(Into::into))
        .unwrap();
    wait_until(|| !pool_b.connected_peers().contains(&c.id())).await;
    pool_b.close();
    pool_c.close();
}

#[tokio::test]
async fn a_forgotten_group_cannot_be_repinned_by_a_pool_push_at_capacity() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let (gid, manifest, _) = seed_group(&[&a, &b], 1, true);
    let pool_b = pool_for(&b, &gid, direct_dialers());
    group_forget(&b.store, &b.id(), &gid).unwrap();
    assert!(b.store.load_group_book().unwrap().manifest(&gid).is_none());

    let params = GroupBuildParams::new(now());
    for seed in 0..u8::try_from(MAX_LOCAL_GROUPS).unwrap() {
        let key = SigningKeypair::from_seed([0xC0 + seed; 32]);
        let fid = group_id_from_root(key.public_key());
        let root = GroupMember::new(
            StaticKeypair::from_scalar([0xC0 + seed; 32]).public_bytes(),
            "root",
            key.public_key(),
            vec![],
            vec![format!("group.send:{fid}")],
        );
        let (m, s) = create_group(&key, "full", 1, root, params).unwrap();
        let (m, _) = add_member(
            &m,
            &GroupSigner::root(&key),
            b.member("b", &fid, true),
            &s,
            params,
        )
        .unwrap();
        store_manifest(&b, &m, None);
    }

    let refused = pool_b.ingest_manifest(&manifest).await;
    assert!(
        matches!(
            refused,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{refused:?}"
    );
    assert!(b.store.load_group_book().unwrap().manifest(&gid).is_none());
    pool_b.close();
}

#[tokio::test]
async fn pool_open_refuses_an_identity_whose_host_id_differs_from_device_id() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let (gid, _, _) = seed_group(&[&a, &b], 1, true);
    let other_host = Arc::new((*b.identity).clone().with_host_id("not-the-device-id"));
    let r = GroupPool::open(
        b.store.clone(),
        other_host,
        &gid,
        GroupPoolConfig::new(direct_dialers()),
        None,
    );
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))),
        "{:?}",
        r.err()
    );
}

/// An ordinary paired session from a member that is not an admin is refused by the pool, and
/// the runtime helper refuses its `0x0B`: no key is installed either way.
#[tokio::test]
async fn ordinary_session_from_a_non_admin_cannot_install_a_rendezvous_key() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let b = Node::new(1).await;
    let e = Node::new(4).await;
    let (gid, manifest, secrets) = seed_group(&[&a, &b, &e], 1, false);
    store_manifest(&e, &manifest, None);
    e.store
        .update_group_book(|book| {
            book.install_secrets(&gid, secrets.clone())
                .map_err(Into::into)
        })
        .unwrap();
    pair(&b, &e, None);
    let pool_b = pool_for(&b, &gid, direct_dialers());

    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let e_identity = Arc::clone(&e.identity);
    let mut e_roster = e.store.load_roster().unwrap();
    let b_id = b.id();
    let pushed = secrets.clone();
    let push_gid = gid.clone();
    let dial = tokio::spawn(async move {
        let stream = DirectDialer::new().dial(&addr.to_string()).await.unwrap();
        let mut s = SessionDriver::connect(stream, &e_identity, &b_id, None, &mut e_roster, now())
            .await
            .unwrap();
        let _ = s.send_group_rendezvous(&pushed, &push_gid).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let stream = listener.accept().await.unwrap();
    let verdict = pool_b.accept(stream).await;
    assert!(
        matches!(
            verdict,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{verdict:?}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), dial).await;
    assert!(b.store.load_group_book().unwrap().secrets(&gid).is_none());

    let frame =
        decode_group_rendezvous_frame(&secrets.to_rendezvous_frame(&gid).unwrap()[..]).unwrap();
    let outcome = handle_session_group_frame(
        &b.store,
        &b.id(),
        &e.id(),
        &SessionEvent::GroupRendezvousReceived(frame),
    )
    .unwrap();
    assert_eq!(outcome.kind, GroupFrameKind::Rendezvous);
    assert_eq!(outcome.group_id, gid);
    assert_eq!(outcome.seq, secrets.seq());
    assert!(!outcome.ingested);
    assert!(outcome.error.is_some());
    assert!(b.store.load_group_book().unwrap().secrets(&gid).is_none());
    assert!(
        handle_session_group_frame(&b.store, &b.id(), &e.id(), &SessionEvent::AppData(vec![1]))
            .is_none()
    );
    pool_b.close();
}

#[tokio::test]
async fn parked_poll_event_returns_promptly_after_close() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let (gid, _, _) = seed_group(&[&a, &b], 1, true);
    let pool = pool_for(&b, &gid, direct_dialers());

    let poller = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let event = pool.poll_event(Duration::from_secs(30)).await;
            (event.is_none(), started.elapsed())
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    pool.close();
    let (none, elapsed) = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("poll_event stayed parked after close")
        .unwrap();
    assert!(none);
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert!(pool.poll_event(Duration::from_secs(30)).await.is_none());
}

fn state_dir_snapshot(node: &Node) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(node.store.dir())
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap_or_default();
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                bytes,
            )
        })
        .collect();
    files.sort();
    files
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_for_in_flight_state_writes_and_none_follow_it() {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let (gid, manifest, secrets) = seed_group(&[&a, &b], 1, true);
    pair(&a, &b, None);
    let pool_b = pool_for(&b, &gid, direct_dialers());

    let signer = GroupSigner::root(a.identity.signing_key());
    let (renewed, _) =
        renew_manifest(&manifest, &signer, &secrets, GroupBuildParams::new(now())).unwrap();
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let a_identity = Arc::clone(&a.identity);
    let mut a_roster = a.store.load_roster().unwrap();
    let b_id = b.id();
    let dial = tokio::spawn(async move {
        let stream = DirectDialer::new().dial(&addr.to_string()).await.unwrap();
        let mut s = SessionDriver::connect(stream, &a_identity, &b_id, None, &mut a_roster, now())
            .await
            .unwrap();
        s.send_group_manifest(&renewed).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Hold the group book lock so the admin push the pool applies parks inside its store access.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(b.store.groups_lock_path())
        .unwrap();
    lock.lock().unwrap();
    let stream = listener.accept().await.unwrap();
    assert_eq!(pool_b.accept(stream).await.unwrap(), a.id());
    tokio::time::sleep(Duration::from_millis(300)).await;

    let closer = {
        let pool = pool_b.clone();
        std::thread::spawn(move || pool.close())
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let returned_early = closer.is_finished();
    lock.unlock().unwrap();
    closer.join().unwrap();
    assert!(
        !returned_early,
        "close returned while a state store access was still in flight"
    );

    let settled = state_dir_snapshot(&b);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        settled,
        state_dir_snapshot(&b),
        "the pool wrote to the state dir after close returned"
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), dial).await;
}

/// The inner stream and the held `msg3` of a parked [`CaptureStream`].
type Released = tokio::sync::oneshot::Sender<(Box<dyn PathStream>, Vec<u8>)>;

/// Forwards until the first read, then buffers writes until one complete outer frame (the
/// initiator's `msg3`) is held, signals `captured`, and parks. Dropping it hands the inner
/// stream and the held frame to the test.
struct CaptureStream {
    inner: Option<Box<dyn PathStream>>,
    read: bool,
    held: Vec<u8>,
    captured: tokio::sync::watch::Sender<bool>,
    released: Option<Released>,
}

impl Drop for CaptureStream {
    fn drop(&mut self) {
        if let (Some(inner), Some(tx)) = (self.inner.take(), self.released.take()) {
            let _ = tx.send((inner, std::mem::take(&mut self.held)));
        }
    }
}

#[async_trait]
impl PathStream for CaptureStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        None
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if !self.read {
            return self.inner.as_mut().unwrap().send_chunk(bytes).await;
        }
        self.held.extend_from_slice(bytes);
        let complete = self.held.len() >= 2
            && self.held.len() >= 2 + usize::from(u16::from_be_bytes([self.held[0], self.held[1]]));
        if complete {
            let _ = self.captured.send(true);
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.read = true;
        self.inner.as_mut().unwrap().recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn into_split(mut self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        self.inner.take().unwrap().into_split()
    }
}

/// Maps the hints `path_a` and `path_b` to one listener. The first `path_b` dial goes through a
/// [`CaptureStream`]; `path_a` dials only once that stream captured its `msg3`. Once `only_a`
/// is set, `path_b` refuses.
struct TwoPathDialer {
    target: String,
    path_a: String,
    path_b: String,
    captured_tx: tokio::sync::watch::Sender<bool>,
    captured_rx: tokio::sync::watch::Receiver<bool>,
    released: Mutex<Option<Released>>,
    only_a: AtomicBool,
}

#[async_trait]
impl PathDialer for TwoPathDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        if endpoint == self.path_a {
            let mut rx = self.captured_rx.clone();
            rx.wait_for(|c| *c)
                .await
                .map_err(|_| RuntimeError::Closed)?;
            return DirectDialer::new().dial(&self.target).await;
        }
        if endpoint != self.path_b || self.only_a.load(Ordering::Acquire) {
            return Err(RuntimeError::Protocol("path refused".to_owned()));
        }
        let stream = DirectDialer::new().dial(&self.target).await?;
        let Some(released) = self.released.lock().unwrap().take() else {
            return Ok(stream);
        };
        Ok(Box::new(CaptureStream {
            inner: Some(stream),
            read: false,
            held: Vec::new(),
            captured: self.captured_tx.clone(),
            released: Some(released),
        }))
    }
}

/// G5: an initiator races two paths to a first-contact sibling and keeps only one. The
/// responder commits only the kept path: the discarded path's late `msg3` neither replaces
/// the kept link nor overwrites the pairwise secrets the two ends agreed on.
#[tokio::test]
async fn responder_commits_only_the_path_the_initiator_kept() {
    let mut a = Node::new(0).await;
    drop(a.listener.take());
    let b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let path_a = "127.0.0.2:1".to_owned();
    let path_b = "127.0.0.3:1".to_owned();
    let gid = group_id_from_root(a.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let (mut manifest, mut secrets) = create_group(
        a.identity.signing_key(),
        "multipath",
        2,
        a.member("root", &gid, true),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(a.identity.signing_key());
    let mut c_member = c.member("c", &gid, true);
    c_member.endpoints = vec![format!("direct:{path_b}"), format!("direct:{path_a}")];
    for member in [b.member("b", &gid, true), c_member] {
        (manifest, secrets) = add_member(&manifest, &signer, member, &secrets, params).unwrap();
    }
    for node in [&a, &b, &c] {
        store_manifest(node, &manifest, Some(&secrets));
    }

    let (captured_tx, captured_rx) = tokio::sync::watch::channel(false);
    let (released_tx, released_rx) = tokio::sync::oneshot::channel();
    let dialer = Arc::new(TwoPathDialer {
        target: c.addr.to_string(),
        path_a,
        path_b,
        captured_tx,
        captured_rx,
        released: Mutex::new(Some(released_tx)),
        only_a: AtomicBool::new(false),
    });
    let pool_b = pool_for(&b, &gid, vec![Arc::clone(&dialer) as Arc<dyn PathDialer>]);
    let pool_c = pool_for(&c, &gid, direct_dialers());
    let mut listener = c.listener.take().unwrap();
    let (accepts_tx, mut accepts) = tokio::sync::mpsc::unbounded_channel();
    let server_pool = pool_c.clone();
    tokio::spawn(async move {
        while let Ok(stream) = listener.accept().await {
            let pool = server_pool.clone();
            let _ = accepts_tx.send(tokio::spawn(async move { pool.accept(stream).await }));
        }
    });

    let report = pool_b.broadcast(None, b"w").await.unwrap();
    assert_eq!(report.delivered, ids([c.id()]), "{report:?}");
    let acc_b = accepts.recv().await.unwrap();
    let acc_a = accepts.recv().await.unwrap();
    let kept = tokio::time::timeout(Duration::from_secs(5), acc_a)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.unwrap(), b.id());
    expect_event(
        &pool_c,
        Duration::from_secs(5),
        |e| matches!(e, GroupEvent::AppData { payload, .. } if payload == b"w"),
    )
    .await;
    let pw_a = pairwise(&b, &gid, &c).expect("b persisted the kept path");
    assert_eq!(pairwise(&c, &gid, &b).as_ref(), Some(&pw_a));

    let (mut discarded, msg3) = tokio::time::timeout(Duration::from_secs(5), released_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!msg3.is_empty());
    discarded.send_chunk(&msg3).await.unwrap();
    let _ = discarded.close().await;
    drop(discarded);
    let late = tokio::time::timeout(Duration::from_secs(15), acc_b)
        .await
        .unwrap()
        .unwrap();
    assert!(late.is_err(), "the discarded path was committed: {late:?}");
    assert_eq!(pairwise(&b, &gid, &c).as_ref(), Some(&pw_a));
    assert_eq!(pairwise(&c, &gid, &b).as_ref(), Some(&pw_a));
    assert!(pool_b.connected_peers().contains(&c.id()));
    assert!(pool_c.connected_peers().contains(&b.id()));

    // Without the bootstrap on either end, the agreed pairwise secret still connects.
    let (renewed, _) =
        renew_manifest(&manifest, &signer, &secrets, GroupBuildParams::new(now())).unwrap();
    store_manifest(&b, &renewed, None);
    store_manifest(&c, &renewed, None);
    wait_until(|| {
        pool_b.manifest().unwrap().seq == renewed.seq
            && pool_c.manifest().unwrap().seq == renewed.seq
    })
    .await;
    dialer.only_a.store(true, Ordering::Release);
    pool_b.disconnect_all();
    pool_c.disconnect_all();
    let report = pool_b.broadcast(None, b"pairwise-only").await.unwrap();
    assert_eq!(report.delivered, ids([c.id()]), "{report:?}");
    assert_eq!(pairwise(&c, &gid, &b).as_ref(), Some(&pw_a));
    pool_b.close();
    pool_c.close();
}

/// What a revoked ordinary peer `a` observes dialing `to_addr` over `wire`: the close code it
/// received after `Established` (Wire v1, or a Wire v2 `msg3` race), its `msg2` refusal (Wire
/// v2), or neither.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    Closed(u16),
    PeerRefused,
    Silent,
}

async fn probe_as_revoked(a: &Node, b: &Node, wire: u8, to_addr: String) -> Probe {
    let stream = DirectDialer::new().dial(&to_addr).await.unwrap();
    let mut roster = a.store.load_roster().unwrap();
    if wire == 2 {
        match V2SessionDriver::connect(stream, &a.identity, &b.id(), None, &mut roster, now()).await
        {
            Err(err) if err.refusal().is_some() => Probe::PeerRefused,
            Err(_) => Probe::Silent,
            Ok(mut session) => tokio::time::timeout(Duration::from_secs(5), async {
                match session.next_event_now(&mut roster).await {
                    Ok(Some(SessionEvent::Closed { code, .. })) => Probe::Closed(code),
                    _ => Probe::Silent,
                }
            })
            .await
            .unwrap(),
        }
    } else {
        let mut session =
            SessionDriver::connect(stream, &a.identity, &b.id(), None, &mut roster, now())
                .await
                .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match session.next_event_now(&mut roster).await {
                    Ok(Some(SessionEvent::Closed { code, .. })) => return Probe::Closed(code),
                    Ok(Some(_)) => {}
                    _ => return Probe::Silent,
                }
            }
        })
        .await
        .unwrap()
    }
}

/// REF-21: a revoked ordinary peer probes a group pool and then the endpoint's ordinary
/// dispatcher. The pool never refuses (a refusal would link the group endpoint to the host);
/// the dispatcher, which is the endpoint's ordinary listener, does.
async fn group_isolation(wire: u8) {
    let a = Node::new(0).await;
    let b = Node::new(1).await;
    let c = Node::new(2).await;
    let secrets = V2PeerSecrets::new([0x5A; 32], [0x5B; 32]);
    pair(&a, &b, (wire == 2).then_some(&secrets));
    let (gid, _, _) = seed_rooted(&c, &[&b], wire);
    b.store
        .update_roster(|r| {
            r.revoke_peer_at(&a.id(), true, now())?;
            Ok(())
        })
        .unwrap();

    let pool = pool_for(&b, &gid, direct_dialers());
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr().to_string();
    let accept = tokio::spawn({
        let pool = pool.clone();
        async move {
            // A host daemon may probe a fresh loopback port with a stray request: skip it.
            let stream = loop {
                let mut stream = listener.accept().await.unwrap();
                let peeked = tokio::time::timeout(
                    Duration::from_secs(2),
                    tendril_runtime::peek_exact(stream.as_mut(), 3),
                )
                .await;
                if let Ok(Ok(prefix)) = peeked
                    && prefix.starts_with(b"TND")
                {
                    break Box::new(tendril_runtime::PrefixedPathStream::new(stream, prefix))
                        as Box<dyn PathStream>;
                }
            };
            pool.accept(stream).await
        }
    });
    let seen = probe_as_revoked(&a, &b, wire, addr).await;
    let verdict = accept.await.unwrap();
    assert!(verdict.is_err(), "{verdict:?}");
    assert_eq!(seen, Probe::Silent, "a group pool must never refuse");
    pool.close();

    let mut b = b;
    let hub = Arc::new(GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        GroupPoolConfig::new(direct_dialers()),
        None,
    ));
    assert_eq!(hub.sync().unwrap().len(), 1);
    let mut routed = spawn_hub_server(Arc::clone(&hub), b.listener.take().unwrap());
    let seen = probe_as_revoked(&a, &b, wire, b.addr.to_string()).await;
    let expected = if wire == 2 {
        Probe::PeerRefused
    } else {
        Probe::Closed(4001)
    };
    assert_eq!(seen, expected, "the ordinary dispatcher refuses");
    let verdict = next_routed(&mut routed).await;
    assert!(verdict.starts_with("refused:"), "{verdict}");
    hub.close();
}

#[tokio::test]
async fn ref_21_group_pool_never_refuses_wire_v1_but_the_hub_does() {
    group_isolation(1).await;
}

#[tokio::test]
async fn ref_21_group_pool_never_refuses_wire_v2_but_the_hub_does() {
    group_isolation(2).await;
}
