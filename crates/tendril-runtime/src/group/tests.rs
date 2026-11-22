//! Interleave tests that need the pool's test-only hooks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::grants::{RevocationListUnsigned, sign_crl};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets, add_member,
    create_group, group_id_from_root, remove_member, renew_manifest, sign_group_manifest,
};
use tendril_core::identity::EndpointIdentity;

use super::{GroupEvent, GroupPool, GroupPoolConfig};
use crate::driver::current_unix_secs;
use crate::provider::PathDialer;
use crate::providers::{DirectDialer, DirectListener};
use crate::store::StateStore;

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
            StaticKeypair::from_scalar([0x41 + n; 32]),
            SigningKeypair::from_seed([0x51 + n; 32]),
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

    fn member(&self, gid: &str) -> GroupMember {
        GroupMember::new(
            self.identity.static_key().public_bytes(),
            "m",
            self.identity.signing_key().public_key(),
            vec![self.hint.clone()],
            vec![format!("group.recv:{gid}"), format!("group.send:{gid}")],
        )
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

/// Builds a group rooted at `root` with `others` as members and stores it, with its key, in
/// every node's book.
fn seed(root: &Node, others: &[&Node], wire: u8) -> (String, GroupManifest, V2GroupSecrets) {
    let gid = group_id_from_root(root.identity.signing_key().public_key());
    let params = GroupBuildParams::new(current_unix_secs());
    let (mut manifest, mut secrets) = create_group(
        root.identity.signing_key(),
        "hooks",
        wire,
        root.member(&gid),
        params,
    )
    .unwrap();
    let signer = GroupSigner::root(root.identity.signing_key());
    for node in others {
        (manifest, secrets) =
            add_member(&manifest, &signer, node.member(&gid), &secrets, params).unwrap();
    }
    for node in std::iter::once(root).chain(others.iter().copied()) {
        store(node, &manifest, Some(&secrets));
    }
    (gid, manifest, secrets)
}

fn store(node: &Node, manifest: &GroupManifest, secrets: Option<&V2GroupSecrets>) {
    node.store
        .update_group_book(|book| {
            book.ingest_group_manifest(manifest, current_unix_secs(), None)?;
            if let Some(s) = secrets {
                book.install_secrets(&manifest.group_id, s.clone())?;
            }
            Ok(())
        })
        .unwrap();
}

fn arm(hook: &super::TestHook, f: impl FnOnce() + Send + 'static) {
    *hook.lock().unwrap() = Some(Box::new(f));
}

fn hook_fired(hook: &super::TestHook) -> bool {
    hook.lock().unwrap().is_none()
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < deadline, "condition not reached");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn no_app_data(pool: &GroupPool, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_millis(400);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool.poll_event(left).await {
            Some(GroupEvent::AppData { payload: p, .. }) if p == payload => {
                panic!("unexpected app data {payload:?}")
            }
            Some(_) => {}
            None => return,
        }
    }
}

fn key_of(node: &Node, gid: &str) -> Option<[u8; 32]> {
    node.store
        .load_group_book()
        .unwrap()
        .secrets(gid)
        .map(|s| *s.group_rendezvous_key())
}

/// G2: a revocation and key rotation landing between pairwise persistence and the refresh in
/// `install` must refuse the link: no slot, no pairwise secret, and no rotated key pushed.
#[tokio::test]
async fn revoke_and_rotate_after_pairwise_persistence_refuses_the_link() {
    let mut b = Node::new(1).await;
    let mut c = Node::new(2).await;
    let (gid, m2, s2) = seed(&b, &[&c], 2);
    let pool_b = b.serve(&gid);
    let pool_c = c.serve(&gid);
    let (m3, s3) = remove_member(
        &m2,
        &GroupSigner::root(b.identity.signing_key()),
        &c.id(),
        &s2,
        GroupBuildParams::new(current_unix_secs()),
    )
    .unwrap();
    let rotated = *s3.group_rendezvous_key();
    let b_store = b.store.clone();
    arm(&pool_b.inner.hooks.after_pairwise_persist, move || {
        b_store
            .update_group_book(|book| {
                book.ingest_group_manifest(&m3, current_unix_secs(), None)?;
                book.install_secrets(&m3.group_id, s3)?;
                Ok(())
            })
            .unwrap();
    });

    let report = pool_b.broadcast(None, b"race").await.unwrap();
    assert!(hook_fired(&pool_b.inner.hooks.after_pairwise_persist));
    assert!(!report.delivered.contains(&c.id()), "{report:?}");
    assert!(!pool_b.connected_peers().contains(&c.id()));
    let book = b.store.load_group_book().unwrap();
    assert!(book.pairwise_secrets(&gid, &c.id()).is_none());
    no_app_data(&pool_c, b"race").await;
    assert_ne!(
        key_of(&c, &gid),
        Some(rotated),
        "revoked member got the rotated key"
    );
    pool_b.close();
    pool_c.close();
}

/// G1: a root CRL entry landing after `sync` picked its targets but before the write must stop
/// both the `0x0A` and the `0x0B` to that member.
#[tokio::test]
async fn crl_entry_before_the_write_blocks_admin_sync_frames() {
    let mut b = Node::new(3).await;
    let mut c = Node::new(4).await;
    let (gid, m2, s2) = seed(&b, &[&c], 2);
    let pool_b = b.serve(&gid);
    let pool_c = c.serve(&gid);
    let report = pool_b.sync().await.unwrap();
    assert_eq!(report.delivered, vec![c.id()], "{report:?}");

    let (m3, s3) = renew_manifest(
        &m2,
        &GroupSigner::root(b.identity.signing_key()),
        &s2,
        GroupBuildParams::new(current_unix_secs()),
    )
    .unwrap();
    store(&b, &m3, Some(&s3));
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: b.id(),
            seq: 1,
            revoked_devices: vec![c.id()],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        b.identity.signing_key(),
    )
    .unwrap();
    let b_store = b.store.clone();
    let issuer = b.id();
    let issuer_pub = b.identity.signing_key().public_key().clone();
    arm(&pool_b.inner.hooks.before_write, move || {
        b_store
            .update_roster(|r| r.ingest_crl(crl, &issuer, &issuer_pub).map_err(Into::into))
            .unwrap();
    });

    let report = pool_b.sync().await.unwrap();
    assert!(hook_fired(&pool_b.inner.hooks.before_write));
    assert!(report.delivered.is_empty(), "{report:?}");
    assert!(!pool_b.connected_peers().contains(&c.id()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let c_book = c.store.load_group_book().unwrap();
    assert_eq!(c_book.manifest(&gid).unwrap().seq, m2.seq, "0x0A was sent");
    assert_eq!(
        c_book.secrets(&gid).unwrap().seq(),
        s2.seq(),
        "0x0B was sent"
    );
    pool_b.close();
    pool_c.close();
}

/// G3: a capability removed while a write waits for the writer lock invalidates that write;
/// the link itself stays up.
#[tokio::test]
async fn capability_removed_before_the_writer_lock_drops_the_write() {
    let mut b = Node::new(5).await;
    let mut c = Node::new(6).await;
    let (gid, m2, _) = seed(&b, &[&c], 1);
    let pool_b = b.serve(&gid);
    let pool_c = c.serve(&gid);
    let report = pool_b.broadcast(None, b"warm").await.unwrap();
    assert_eq!(report.delivered, vec![c.id()], "{report:?}");

    let mut unsigned = m2.unsigned();
    unsigned.seq += 1;
    let target = unsigned
        .members
        .iter_mut()
        .find(|m| m.device_id == c.id())
        .unwrap();
    target.caps.retain(|cap| !cap.starts_with("group.recv"));
    let m3 = sign_group_manifest(unsigned, b.identity.signing_key()).unwrap();
    let b_store = b.store.clone();
    arm(&pool_b.inner.hooks.before_write, move || {
        b_store
            .update_group_book(|book| {
                book.ingest_group_manifest(&m3, current_unix_secs(), None)?;
                Ok(())
            })
            .unwrap();
    });

    let report = pool_b.broadcast(None, b"after").await.unwrap();
    assert!(hook_fired(&pool_b.inner.hooks.before_write));
    assert!(report.delivered.is_empty(), "{report:?}");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    no_app_data(&pool_c, b"after").await;
    assert!(pool_b.connected_peers().contains(&c.id()));
    wait_until(|| pool_b.manifest().unwrap().seq == m2.seq + 1).await;
    pool_b.close();
    pool_c.close();
}

/// Ordinarily pairs the root `root` with `member` over Wire v1.
fn pair_v1(root: &Node, member: &Node) {
    root.store
        .update_roster(|r| {
            r.record_pending_pair(
                *member.identity.static_key().public_bytes(),
                Some(member.identity.signing_key().public_key().clone()),
                "peer".into(),
                "peer".into(),
                "1111".into(),
            )?;
            r.confirm_peer(&member.id(), Some("1111"))?;
            Ok(())
        })
        .unwrap();
    member
        .store
        .update_roster(|r| {
            r.insert_pinned_host(
                root.id(),
                "root".into(),
                *root.identity.static_key().public_bytes(),
                Some(root.identity.signing_key().public_key().clone()),
                0,
                vec![],
            )?;
            Ok(())
        })
        .unwrap();
}

/// G1 on the onboarding path: a root CRL entry landing after the admin push opened the
/// member's ordinary session but before the write stops both the `0x0A` and the `0x0B`.
#[tokio::test]
async fn crl_entry_before_the_write_blocks_an_ordinary_admin_push() {
    let mut b = Node::new(7).await;
    let mut c = Node::new(8).await;
    let (gid, m2, _) = seed(&b, &[&c], 2);
    c.store
        .update_group_book(|book| {
            book.forget_group(&gid);
            book.ingest_group_manifest(&m2, current_unix_secs(), None)?;
            Ok(())
        })
        .unwrap();
    pair_v1(&b, &c);
    let pool_b = b.serve(&gid);
    let pool_c = c.serve(&gid);
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: b.id(),
            seq: 1,
            revoked_devices: vec![c.id()],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        b.identity.signing_key(),
    )
    .unwrap();
    let b_store = b.store.clone();
    let issuer = b.id();
    let issuer_pub = b.identity.signing_key().public_key().clone();
    arm(&pool_b.inner.hooks.before_write, move || {
        b_store
            .update_roster(|r| r.ingest_crl(crl, &issuer, &issuer_pub).map_err(Into::into))
            .unwrap();
    });

    let report = pool_b.sync().await.unwrap();
    assert!(hook_fired(&pool_b.inner.hooks.before_write));
    assert!(report.delivered.is_empty(), "{report:?}");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(key_of(&c, &gid).is_none(), "0x0B was sent");
    pool_b.close();
    pool_c.close();
}
