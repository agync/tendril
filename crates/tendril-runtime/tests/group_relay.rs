//! Group sibling links over relays: `/v2/relay` group mailboxes, `/v1/relay` identity
//! mailboxes, relay auth, registration ownership, and admin sync over an ordinary mailbox.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets, add_member,
    create_group, derive_group_mailbox_secret, group_id_from_root, remove_member,
};
use tendril_core::identity::EndpointIdentity;
use tendril_core::relay_auth::{RelayAuthScope, RelayAuthSecret};
use tendril_core::roster::V2PeerSecrets;
use tendril_core::v2::epoch_for_unix;
use tendril_relay::RelayConfig;
use tendril_runtime::{
    EmbeddedRelay, GroupEvent, GroupHub, GroupPool, GroupPoolConfig, InboundSession, PathDialer,
    PathListener, RelayClientAuth, RelayDialer, RelayV2Dialer, RelayV2Listener, RuntimeError,
    StateStore, V2ResponderState, handle_session_group_frame,
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
}

impl Node {
    fn new(n: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_or_create(dir.path()).unwrap();
        let identity = Arc::new(EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x21 + n; 32]),
            SigningKeypair::from_seed([0x31 + n; 32]),
        ));
        Self {
            _dir: dir,
            store,
            identity,
        }
    }

    fn id(&self) -> String {
        self.identity.device_id()
    }

    fn member(&self, gid: &str, hints: Vec<String>) -> GroupMember {
        GroupMember::new(
            self.identity.static_key().public_bytes(),
            "m",
            self.identity.signing_key().public_key(),
            hints,
            vec![format!("group.recv:{gid}"), format!("group.send:{gid}")],
        )
    }
}

fn store(node: &Node, manifest: &GroupManifest, secrets: Option<&V2GroupSecrets>) {
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

/// A Wire v2 group rooted at `nodes[0]`; member `i` advertises `hints[i]`. Stored with the key
/// in every node.
fn seed(nodes: &[&Node], hints: &[Vec<String>]) -> (String, GroupManifest, V2GroupSecrets) {
    let root = nodes[0];
    let gid = group_id_from_root(root.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let (mut manifest, mut secrets) = create_group(
        root.identity.signing_key(),
        "relay",
        2,
        root.member(&gid, hints[0].clone()),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(root.identity.signing_key());
    for (i, node) in nodes.iter().enumerate().skip(1) {
        (manifest, secrets) = add_member(
            &manifest,
            &signer,
            node.member(&gid, hints[i].clone()),
            &secrets,
            params,
        )
        .unwrap();
    }
    for node in nodes {
        store(node, &manifest, Some(&secrets));
    }
    (gid, manifest, secrets)
}

fn open(node: &Node, gid: &str, config: GroupPoolConfig) -> GroupPool {
    GroupPool::open(
        node.store.clone(),
        Arc::clone(&node.identity),
        gid,
        config,
        None,
    )
    .unwrap()
}

fn relay_only() -> GroupPoolConfig {
    GroupPoolConfig::new(vec![]).with_relay_listen(true)
}

async fn relay(auth: Option<&RelayAuthSecret>) -> EmbeddedRelay {
    EmbeddedRelay::start(RelayConfig {
        host: "127.0.0.1".to_owned(),
        auth_secret: auth.map(|s| zeroize::Zeroizing::new(s.as_bytes().to_vec())),
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .unwrap()
}

fn mailbox(secrets: &V2GroupSecrets, device: &str) -> [u8; 32] {
    *derive_group_mailbox_secret(secrets.group_rendezvous_key(), secrets.seq(), device)
}

struct Prober {
    url: String,
    epoch: u64,
    auth: RelayClientAuth,
}

impl Prober {
    fn new(url: &str, auth: RelayClientAuth) -> Self {
        Self {
            url: url.to_owned(),
            epoch: epoch_for_unix(now()),
            auth,
        }
    }

    /// One dial of `secret`, with no retry.
    async fn probe_once(&self, secret: [u8; 32]) -> Result<(), RuntimeError> {
        RelayV2Dialer::new(secret)
            .with_auth(self.auth.clone())
            .connect_for_epoch(&self.url, self.epoch)
            .await
            .map(drop)
    }

    /// Dials `secret` until the relay answers. A timeout means a loaded host, not a mailbox
    /// state, so it is retried until a hard 10 s deadline; every other result is returned as is.
    async fn probe(&self, secret: [u8; 32]) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let res = match tokio::time::timeout(remaining, self.probe_once(secret)).await {
                Ok(res) => res,
                Err(_) => return Err(RuntimeError::Timeout("probe deadline")),
            };
            if !matches!(res, Err(RuntimeError::Timeout(_))) || Instant::now() >= deadline {
                return res;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_registered(&self, secret: [u8; 32]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.probe(secret).await.is_err() {
            assert!(Instant::now() < deadline, "mailbox never registered");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_offline(&self, secret: [u8; 32]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let res = self.probe(secret).await;
            if is_offline(&res) {
                return;
            }
            assert!(res.is_ok(), "unexpected probe error: {res:?}");
            assert!(Instant::now() < deadline, "mailbox never released");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn is_offline(res: &Result<(), RuntimeError>) -> bool {
    matches!(res, Err(e @ RuntimeError::RelayOffline(_)) if e.to_string() == "v2 relay dial rejected: offline")
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

async fn expect_data(pool: &GroupPool, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool.poll_event(left).await {
            Some(GroupEvent::AppData { payload: p, .. }) if p == payload => return,
            Some(_) => {}
            None => panic!("app data {payload:?} did not arrive"),
        }
    }
}

/// Broadcasts until `peer` is delivered, bounded; the target registers asynchronously.
async fn deliver_to(pool: &GroupPool, peer: &Node, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let report = pool.broadcast(None, payload).await.unwrap();
        if report.delivered.contains(&peer.id()) {
            return;
        }
        assert!(Instant::now() < deadline, "never delivered: {report:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn relay_only_siblings_link_and_exchange_group_traffic() {
    let relay = relay(None).await;
    let url = relay.ws_v2_url();
    let prober = Prober::new(&url, RelayClientAuth::None);
    let a = Node::new(0);
    let b = Node::new(1);
    let c = Node::new(2);
    let (gid, _, secrets) = seed(
        &[&a, &b, &c],
        &[vec![], vec![url.clone()], vec![url.clone()]],
    );
    let pool_b = open(&b, &gid, relay_only());
    let pool_c = open(&c, &gid, relay_only());
    prober.wait_registered(mailbox(&secrets, &c.id())).await;

    let report = pool_b.broadcast(None, b"over relay").await.unwrap();
    assert_eq!(report.delivered, vec![c.id()], "{report:?}");
    expect_data(&pool_c, b"over relay").await;
    let pw = pairwise(&b, &gid, &c);
    assert!(pw.is_some());
    wait_until(|| pairwise(&c, &gid, &b) == pw).await;
    pool_b.close();
    pool_c.close();
}

#[tokio::test]
async fn relay_mailbox_rotation_is_per_member_and_takes_the_old_registration_offline() {
    let relay = relay(None).await;
    let url = relay.ws_v2_url();
    let prober = Prober::new(&url, RelayClientAuth::None);
    let a = Node::new(10);
    let b = Node::new(11);
    let c = Node::new(12);
    let d = Node::new(13);
    let hints = vec![url.clone()];
    let (gid, m1, s1) = seed(
        &[&a, &b, &c, &d],
        &[vec![], hints.clone(), hints.clone(), hints],
    );
    let pool_b = open(&b, &gid, relay_only());
    let pool_c = open(&c, &gid, relay_only());
    let pool_d = open(&d, &gid, relay_only());
    let old_b = mailbox(&s1, &b.id());
    let old_c = mailbox(&s1, &c.id());
    prober.wait_registered(old_b).await;
    prober.wait_registered(mailbox(&s1, &d.id())).await;

    let (m2, s2) = remove_member(
        &m1,
        &GroupSigner::root(a.identity.signing_key()),
        &c.id(),
        &s1,
        GroupBuildParams::new(now()),
    )
    .unwrap();
    store(&b, &m2, Some(&s2));
    store(&d, &m2, Some(&s2));
    prober.wait_offline(old_b).await;
    prober.wait_registered(mailbox(&s2, &b.id())).await;
    prober.wait_registered(mailbox(&s2, &d.id())).await;

    let report = pool_d.broadcast(None, b"rotated").await.unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    expect_data(&pool_b, b"rotated").await;
    let report = pool_c.broadcast(None, b"stale").await.unwrap();
    assert!(report.offline.contains(&b.id()), "{report:?}");
    prober.probe(old_c).await.unwrap();
    pool_b.close();
    pool_c.close();
    pool_d.close();
}

#[tokio::test]
async fn relay_mailbox_needs_relay_auth_on_an_auth_required_relay() {
    let secret = RelayAuthSecret::from_bytes(b"group-relay-mailbox-auth-secret!").unwrap();
    let relay = relay(Some(&secret)).await;
    let url = relay.ws_v2_url();
    let auth = RelayClientAuth::HmacSecret(secret);
    let prober = Prober::new(&url, auth.clone());
    let a = Node::new(20);
    let b = Node::new(21);
    let c = Node::new(22);
    let d = Node::new(23);
    let hints = vec![url.clone()];
    let (gid, _, s1) = seed(
        &[&a, &b, &c, &d],
        &[vec![], hints.clone(), hints.clone(), hints],
    );
    let authed = || relay_only().with_relay_auth(auth.clone());
    let pool_b = open(&b, &gid, authed());
    let pool_c = open(&c, &gid, authed());
    let pool_d = open(&d, &gid, relay_only());
    prober.wait_registered(mailbox(&s1, &b.id())).await;
    prober.wait_registered(mailbox(&s1, &c.id())).await;

    let report = pool_b.broadcast(None, b"authed").await.unwrap();
    assert!(report.delivered.contains(&c.id()), "{report:?}");
    expect_data(&pool_c, b"authed").await;

    let res = prober.probe(mailbox(&s1, &d.id())).await;
    assert!(is_offline(&res), "{res:?}");
    let report = pool_d.broadcast(None, b"unauthed").await.unwrap();
    assert!(report.offline.contains(&b.id()), "{report:?}");
    pool_b.close();
    pool_c.close();
    pool_d.close();
}

/// Asserts that `secret` stays exactly offline for `window`: longer than several book watcher
/// ticks, so a pool that registers it would be seen.
async fn stays_offline(prober: &Prober, secret: [u8; 32], window: Duration) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        let res = prober.probe_once(secret).await;
        assert!(
            !matches!(res, Err(RuntimeError::Timeout(_))),
            "probe timed out inside the observation window"
        );
        assert!(is_offline(&res), "mailbox registered: {res:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn transient_pool_does_not_displace_the_serving_registration() {
    let relay = relay(None).await;
    let url = relay.ws_v2_url();
    let prober = Prober::new(&url, RelayClientAuth::None);
    let a = Node::new(30);
    let b = Node::new(31);
    let c = Node::new(32);
    let hints = vec![url.clone()];
    let (gid, _, s1) = seed(&[&a, &b, &c], &[vec![], hints.clone(), hints]);
    let pool_c = open(&c, &gid, relay_only());
    let mb = mailbox(&s1, &b.id());
    prober.wait_registered(mailbox(&s1, &c.id())).await;

    let transient = open(&b, &gid, GroupPoolConfig::new(vec![]));
    let report = transient.broadcast(None, b"transient").await.unwrap();
    assert!(report.delivered.contains(&c.id()), "{report:?}");
    stays_offline(&prober, mb, Duration::from_secs(1)).await;
    transient.close();
    drop(transient);

    let serving = open(&b, &gid, relay_only());
    prober.wait_registered(mb).await;
    let transient = open(&b, &gid, GroupPoolConfig::new(vec![]));
    let report = transient.broadcast(None, b"transient again").await.unwrap();
    assert!(report.delivered.contains(&c.id()), "{report:?}");
    transient.close();
    drop(transient);
    prober.probe(mb).await.unwrap();
    deliver_to(&pool_c, &b, b"to serving").await;
    expect_data(&serving, b"to serving").await;
    serving.close();
    pool_c.close();
}

/// Ordinarily pairs `a` and `x` over Wire v2 with shared `secrets`.
fn pair_v2(a: &Node, x: &Node, secrets: &V2PeerSecrets) {
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
            r.upgrade_peer_to_v2(&x.id(), secrets.clone())?;
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
            r.upgrade_peer_to_v2(&a.id(), secrets.clone())?;
            Ok(())
        })
        .unwrap();
}

/// The CLI-serve route on `b`: a hub and a `/v2/relay` listener on `b`'s ordinary pair mailbox
/// for `a`; ordinary sessions are polled and their group frames ingested.
fn serve_ordinary_mailbox(b: &Node, hub: Arc<GroupHub>, mut listener: RelayV2Listener) {
    let store = b.store.clone();
    let local = b.id();
    tokio::spawn(async move {
        let state = Arc::new(V2ResponderState::new());
        while let Ok(stream) = listener.accept().await {
            let hub = Arc::clone(&hub);
            let state = Arc::clone(&state);
            let store = store.clone();
            let local = local.clone();
            tokio::spawn(async move {
                let Ok(InboundSession::OrdinaryV2 { mut session }) =
                    hub.accept(stream, &state, None, None).await
                else {
                    return;
                };
                let mut roster = store.load_roster().unwrap();
                let sender = session.peer_device_id().to_owned();
                while let Ok(Some(event)) = session.next_event_now(&mut roster).await {
                    let _ = handle_session_group_frame(&store, &local, &sender, &event);
                }
            });
        }
    });
}

#[tokio::test]
async fn admin_sync_reaches_a_relay_only_member_over_its_ordinary_mailbox() {
    let relay = relay(None).await;
    let url = relay.ws_v2_url();
    let prober = Prober::new(&url, RelayClientAuth::None);
    let a = Node::new(40);
    let b = Node::new(41);
    let (gid, manifest, secrets) = seed(&[&a, &b], &[vec![], vec![url.clone()]]);
    b.store
        .update_group_book(|book| {
            book.drop_secrets(&gid);
            Ok(())
        })
        .unwrap();
    store(&b, &manifest, None);
    let ordinary = V2PeerSecrets::new([0x5A; 32], [0x5B; 32]);
    pair_v2(&a, &b, &ordinary);
    let pool_a = open(&a, &gid, GroupPoolConfig::new(vec![]));

    let report = pool_a.sync().await.unwrap();
    assert!(report.offline.contains(&b.id()), "{report:?}");

    let hub = Arc::new(GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        relay_only(),
        None,
    ));
    assert_eq!(hub.sync().unwrap().len(), 1);
    let listener = RelayV2Listener::bind(
        url.clone(),
        None,
        *ordinary.mailbox_secret(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    serve_ordinary_mailbox(&b, Arc::clone(&hub), listener);
    prober.wait_registered(*ordinary.mailbox_secret()).await;

    let report = pool_a.sync().await.unwrap();
    assert_eq!(report.delivered, vec![b.id()], "{report:?}");
    wait_until(|| b.store.load_group_book().unwrap().secrets(&gid).is_some()).await;
    prober.wait_registered(mailbox(&secrets, &b.id())).await;
    pool_a.close();
    hub.close();
}

#[tokio::test]
async fn v1_relay_siblings_link_and_revocation_cuts_the_removed_member_off() {
    let relay = relay(None).await;
    let url = relay.ws_url();
    let a = Node::new(50);
    let b = Node::new(51);
    let c = Node::new(52);
    let hints = vec![url.clone()];
    let (gid, m1, s1) = seed(&[&a, &b, &c], &[vec![], hints.clone(), hints]);
    let v1 = || {
        let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(RelayDialer::new())];
        GroupPoolConfig::new(dialers).with_relay_listen(true)
    };
    let pool_b = open(&b, &gid, v1());
    let pool_c = open(&c, &gid, v1());
    deliver_to(&pool_b, &c, b"v1 relay").await;
    expect_data(&pool_c, b"v1 relay").await;
    let pw = pairwise(&b, &gid, &c);
    assert!(pw.is_some());
    wait_until(|| pairwise(&c, &gid, &b) == pw).await;

    let (m2, s2) = remove_member(
        &m1,
        &GroupSigner::root(a.identity.signing_key()),
        &c.id(),
        &s1,
        GroupBuildParams::new(now()),
    )
    .unwrap();
    store(&b, &m2, Some(&s2));
    wait_until(|| pool_b.connected_peers().is_empty()).await;
    // A write on the stale link can still be accepted locally before `c` reads `b`'s close, so
    // the removed member must first lose that link and then fail to dial a new one.
    wait_until(|| pool_c.connected_peers().is_empty()).await;
    let report = pool_c.broadcast(None, b"removed").await.unwrap();
    assert!(!report.delivered.contains(&b.id()), "{report:?}");
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool_b.poll_event(left).await {
            Some(GroupEvent::AppData { payload, .. }) => {
                assert_ne!(payload, b"removed", "removed member delivered data");
            }
            Some(_) => {}
            None => break,
        }
    }
    pool_b.close();
    pool_c.close();
}
