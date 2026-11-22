//! Wire v2 member onboarding: the root pushes the manifest and the rendezvous key over ordinary
//! paired sessions to members that only run a pool listener and hold only the manifest.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets, add_member,
    create_group, decode_group_rendezvous_frame, group_id_from_root, remove_member,
};
use tendril_core::identity::EndpointIdentity;
use tendril_core::roster::V2PeerSecrets;
use tendril_runtime::{
    DirectDialer, DirectListener, GroupEvent, GroupPool, GroupPoolConfig, PathDialer, StateStore,
    ingest_pushed_manifest, ingest_pushed_rendezvous,
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
    hint: String,
}

impl Node {
    async fn new(n: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_or_create(dir.path()).unwrap();
        let identity = Arc::new(EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x21 + n; 32]),
            SigningKeypair::from_seed([0x31 + n; 32]),
        ));
        let listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let hint = format!("direct:{}", listener.local_addr());
        Self {
            _dir: dir,
            store,
            identity,
            listener: Some(listener),
            hint,
        }
    }

    fn id(&self) -> String {
        self.identity.device_id()
    }

    fn member(&self, name: &str, gid: &str) -> GroupMember {
        GroupMember::new(
            self.identity.static_key().public_bytes(),
            name,
            self.identity.signing_key().public_key(),
            vec![self.hint.clone()],
            vec![format!("group.recv:{gid}"), format!("group.send:{gid}")],
        )
    }

    fn secrets(&self, gid: &str) -> Option<V2GroupSecrets> {
        self.store.load_group_book().unwrap().secrets(gid).cloned()
    }

    fn pairwise(&self, gid: &str, peer: &Self) -> Option<V2PeerSecrets> {
        self.store
            .load_group_book()
            .unwrap()
            .pairwise_secrets(gid, &peer.id())
            .cloned()
    }

    fn serve(&mut self, gid: &str) -> GroupPool {
        let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(DirectDialer::new())];
        let pool = GroupPool::open(
            self.store.clone(),
            Arc::clone(&self.identity),
            gid,
            GroupPoolConfig::new(dialers),
            None,
        )
        .unwrap();
        pool.serve(Box::new(self.listener.take().unwrap()));
        pool
    }
}

/// Ordinarily pairs the root `a` with `x`, over Wire v2 when `secrets` is given.
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

fn store_rooted(node: &Node, manifest: &GroupManifest, secrets: &V2GroupSecrets) {
    node.store
        .update_group_book(|book| {
            book.ingest_group_manifest(manifest, now(), None)?;
            book.install_secrets(&manifest.group_id, secrets.clone())?;
            Ok(())
        })
        .unwrap();
}

#[track_caller]
fn wait_until(mut cond: impl FnMut() -> bool) -> impl std::future::Future<Output = ()> {
    let caller = std::panic::Location::caller();
    async move {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(
                Instant::now() < deadline,
                "condition at {caller} not reached"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn expect_data(pool: &GroupPool, sender: &Node, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool.poll_event(left).await {
            Some(GroupEvent::AppData {
                sender_device_id,
                payload: got,
            }) if sender_device_id == sender.id() && got == payload => return,
            Some(_) => {}
            None => panic!("app data {payload:?} from {} not received", sender.id()),
        }
    }
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

struct Trio {
    a: Node,
    b: Node,
    c: Node,
    gid: String,
    root_identity: Arc<EndpointIdentity>,
    m3: GroupManifest,
    s3: V2GroupSecrets,
    pool_a: GroupPool,
    pool_b: GroupPool,
    pool_c: GroupPool,
}

/// Root A onboards B (paired over Wire v2) and then C (paired over Wire v1) into a Wire v2
/// group. B and C each hold only the manifest and run only a pool listener.
async fn onboard_trio() -> Trio {
    let mut a = Node::new(0).await;
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let gid = group_id_from_root(a.identity.signing_key().public_key());
    let params = GroupBuildParams::new(now());
    let root_identity = Arc::clone(&a.identity);
    let signer = GroupSigner::root(root_identity.signing_key());
    let (m1, s1) = create_group(
        a.identity.signing_key(),
        "onboard",
        2,
        a.member("a", &gid),
        params,
    )
    .unwrap();
    let (m2, s2) = add_member(&m1, &signer, b.member("b", &gid), &s1, params).unwrap();
    store_rooted(&a, &m2, &s2);
    pair(&a, &b, Some(&V2PeerSecrets::new([0x91; 32], [0xA1; 32])));
    ingest_pushed_manifest(&b.store, &b.id(), &a.id(), &m2).unwrap();
    assert!(b.secrets(&gid).is_none());

    let pool_a = a.serve(&gid);
    let pool_b = b.serve(&gid);
    let report = pool_a.sync().await.unwrap();
    assert_eq!(report.delivered, vec![b.id()], "{report:?}");
    wait_until(|| b.secrets(&gid).is_some()).await;
    assert_eq!(b.secrets(&gid), Some(s2.clone()));
    assert!(
        pool_a.connected_peers().is_empty(),
        "the admin push is not a sibling link"
    );

    let report = pool_a.broadcast(None, b"a-to-b").await.unwrap();
    assert_eq!(report.delivered, vec![b.id()], "{report:?}");
    expect_data(&pool_b, &a, b"a-to-b").await;
    let report = pool_b.broadcast(None, b"b-to-a").await.unwrap();
    assert_eq!(report.delivered, vec![a.id()], "{report:?}");
    expect_data(&pool_a, &b, b"b-to-a").await;
    assert!(b.pairwise(&gid, &a).is_some());

    let (m3, s3) = add_member(&m2, &signer, c.member("c", &gid), &s2, params).unwrap();
    store_rooted(&a, &m3, &s3);
    pair(&a, &c, None);
    ingest_pushed_manifest(&c.store, &c.id(), &a.id(), &m3).unwrap();
    assert!(c.secrets(&gid).is_none());
    let pool_c = c.serve(&gid);
    let report = pool_a.sync().await.unwrap();
    assert_eq!(report.delivered, sorted(vec![b.id(), c.id()]), "{report:?}");
    wait_until(|| {
        b.secrets(&gid).is_some_and(|s| s.seq() == 3)
            && c.secrets(&gid).is_some_and(|s| s.seq() == 3)
    })
    .await;
    assert_eq!(c.secrets(&gid), Some(s3.clone()));

    let report = pool_b.broadcast(None, b"b-to-c").await.unwrap();
    assert!(report.delivered.contains(&c.id()), "{report:?}");
    expect_data(&pool_c, &b, b"b-to-c").await;
    let report = pool_c.broadcast(None, b"c-to-b").await.unwrap();
    assert!(report.delivered.contains(&b.id()), "{report:?}");
    expect_data(&pool_b, &c, b"c-to-b").await;
    let (pw_b, pw_c) = (b.pairwise(&gid, &c), c.pairwise(&gid, &b));
    assert!(pw_b.is_some());
    assert_eq!(pw_b, pw_c);

    Trio {
        a,
        b,
        c,
        gid,
        root_identity,
        m3,
        s3,
        pool_a,
        pool_b,
        pool_c,
    }
}

#[tokio::test]
async fn admin_sync_onboards_v2_members_over_ordinary_sessions() {
    let t = onboard_trio().await;
    t.pool_a.close();
    t.pool_b.close();
    t.pool_c.close();
}

#[tokio::test]
async fn removed_member_loses_the_rotated_key_and_cannot_reconnect() {
    let t = onboard_trio().await;
    let (a, b, c, gid) = (&t.a, &t.b, &t.c, t.gid.as_str());
    let signer = GroupSigner::root(t.root_identity.signing_key());
    let (m4, s4) =
        remove_member(&t.m3, &signer, &c.id(), &t.s3, GroupBuildParams::new(now())).unwrap();
    store_rooted(a, &m4, &s4);
    let report = t.pool_a.sync().await.unwrap();
    assert_eq!(report.delivered, vec![b.id()], "{report:?}");
    wait_until(|| b.secrets(gid).is_some_and(|s| s.seq() == 4)).await;
    assert_eq!(b.secrets(gid), Some(s4.clone()));
    assert_ne!(
        s4.group_rendezvous_key(),
        t.s3.group_rendezvous_key(),
        "removal rotates the key"
    );
    wait_until(|| !t.pool_b.connected_peers().contains(&c.id())).await;
    assert!(b.pairwise(gid, c).is_none());

    // C still holds seq 3 with its pairwise secret and bootstrap key; B refuses both.
    wait_until(|| !t.pool_c.connected_peers().contains(&b.id())).await;
    let report = t.pool_c.broadcast(None, b"after-removal").await.unwrap();
    assert!(!report.delivered.contains(&b.id()), "{report:?}");
    assert!(!report.delivered.contains(&a.id()), "{report:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!t.pool_b.connected_peers().contains(&c.id()));
    assert!(!t.pool_a.connected_peers().contains(&c.id()));

    // A pushed copy of the rotated key is refused once C learns it was removed.
    ingest_pushed_manifest(&c.store, &c.id(), &a.id(), &m4).unwrap();
    assert!(c.secrets(gid).is_none(), "removal drops C's key material");
    let frame = decode_group_rendezvous_frame(&s4.to_rendezvous_frame(gid).unwrap()[..]).unwrap();
    assert!(ingest_pushed_rendezvous(&c.store, &c.id(), &a.id(), &frame).is_err());
    assert!(c.secrets(gid).is_none());

    t.pool_a.close();
    t.pool_b.close();
    t.pool_c.close();
}
