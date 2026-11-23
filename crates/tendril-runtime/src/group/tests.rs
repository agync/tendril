//! Interleave tests that need the pool's test-only hooks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets, add_member,
    create_group, group_id_from_root, remove_member, renew_manifest, sign_group_manifest,
};
use tendril_core::identity::EndpointIdentity;

use super::{GroupEvent, GroupHub, GroupPool, GroupPoolConfig, InboundSession};
use crate::driver::current_unix_secs;
use crate::error::RuntimeError;
use crate::provider::{PathDialer, PathListener};
use crate::providers::{DirectDialer, DirectListener};
use crate::store::StateStore;
use crate::v2_driver::V2ResponderState;

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

fn signed_list(
    issuer: &str,
    seq: u64,
    revoked: Vec<String>,
    key: &SigningKeypair,
) -> RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: issuer.to_owned(),
            seq,
            revoked_devices: revoked,
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        key,
    )
    .unwrap()
}

/// `member` pins `root` under `label` and stores `list` there, signed by `root`.
fn pin_root_with_list(member: &Node, root: &Node, label: &str, list: RevocationList) {
    let key = root.identity.signing_key().public_key().clone();
    member
        .store
        .update_roster(|r| {
            r.insert_pinned_host(
                label.to_owned(),
                "root".into(),
                *root.identity.static_key().public_bytes(),
                Some(key.clone()),
                0,
                vec![],
            )?;
            r.ingest_crl(list, label, &key)?;
            Ok(())
        })
        .unwrap();
}

fn open_pool(node: &Node, gid: &str) -> GroupPool {
    let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(DirectDialer::new())];
    GroupPool::open(
        node.store.clone(),
        Arc::clone(&node.identity),
        gid,
        GroupPoolConfig::new(dialers),
        None,
    )
    .unwrap()
}

/// A root CRL stored under a host label applies to pool and hub decisions, and a rotated
/// root keyed by its `device_id` fails every decision closed.
#[tokio::test]
async fn root_crl_under_a_host_label_applies_to_pool_decisions() {
    let mut a = Node::new(9).await;
    drop(a.listener.take());
    let mut b = Node::new(10).await;
    let mut c = Node::new(11).await;
    drop(c.listener.take());
    let mut d = Node::new(14).await;
    let (gid, _, _) = seed(&a, &[&b, &c, &d], 1);
    let list = signed_list("root-host", 1, vec![c.id()], a.identity.signing_key());
    pin_root_with_list(&b, &a, "root-host", list);
    let send = format!("group.send:{gid}");
    let pool_b = open_pool(&b, &gid);
    let r = pool_b.authorize_peer(&c.id(), &send);
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::GroupMemberRevoked(_)))),
        "{r:?}"
    );
    pool_b.authorize_peer(&a.id(), &send).unwrap();
    pool_b.close();

    // Hub: the root entry has a Wire v2 floor, the group and the session are Wire v1, so the
    // wire floor narrowing drops the root entry. Its CRL now revokes the local device `b` too
    // and must still empty the group's pins, so the handshake itself refuses the unrevoked `d`.
    let both = signed_list(
        "root-host",
        2,
        vec![c.id(), b.id()],
        a.identity.signing_key(),
    );
    let a_pub = a.identity.signing_key().public_key().clone();
    b.store
        .update_roster(|r| {
            r.ingest_crl(both, "root-host", &a_pub)?;
            r.set_peer_min_wire_version("root-host", 2)?;
            Ok(())
        })
        .unwrap();
    let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(DirectDialer::new())];
    let hub = Arc::new(GroupHub::new(
        b.store.clone(),
        Arc::clone(&b.identity),
        GroupPoolConfig::new(dialers),
        None,
    ));
    assert_eq!(hub.sync().unwrap().len(), 1);
    let mut listener = b.listener.take().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let server_hub = Arc::clone(&hub);
    tokio::spawn(async move {
        let state = V2ResponderState::new();
        while let Ok(stream) = listener.accept().await {
            let verdict = match server_hub.accept(stream, &state, None, None).await {
                Ok(InboundSession::Group { peer_device_id, .. }) => {
                    format!("group:{peer_device_id}")
                }
                Ok(_) => "ordinary".to_owned(),
                Err(err) => format!("refused:{err}"),
            };
            let _ = tx.send(verdict);
        }
    });
    let pool_d = d.serve(&gid);
    pool_d.broadcast(None, b"revoked").await.unwrap();
    let verdict = loop {
        let verdict = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        if !verdict.contains("invalid preamble") {
            break verdict;
        }
    };
    assert!(verdict.starts_with("refused:"), "{verdict}");
    assert!(
        verdict.contains("peer not found"),
        "the hub pinned members of a group whose root CRL revokes the local device: {verdict}"
    );
    pool_d.close();
    hub.close();

    // A root keyed by its device id rotates; its re-signed list no longer verifies under the
    // founding key, so every decision of the pool fails closed and keeps failing.
    let r = Node::new(12).await;
    let m = Node::new(13).await;
    let (gid, _, _) = seed(&r, &[&m], 2);
    let first = signed_list(&r.id(), 1, vec![], r.identity.signing_key());
    pin_root_with_list(&m, &r, &r.id(), first);
    let send = format!("group.send:{gid}");
    let pool_m = open_pool(&m, &gid);
    pool_m.authorize_peer(&r.id(), &send).unwrap();
    let mut rotated = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41 + 12; 32]),
        SigningKeypair::from_seed([0x51 + 12; 32]),
    );
    rotated
        .rotate(
            StaticKeypair::from_scalar([0xD1; 32]),
            SigningKeypair::from_seed([0xD2; 32]),
            current_unix_secs(),
        )
        .unwrap();
    let resigned = signed_list(&r.id(), 2, vec![], rotated.signing_key());
    let new_pub = rotated.signing_key().public_key().clone();
    m.store
        .update_roster(|roster| {
            roster.apply_verified_rotation(
                &r.id(),
                rotated.rotation_chain(),
                rotated.static_key().public_bytes(),
                &new_pub,
            )?;
            roster.ingest_crl(resigned, &r.id(), &new_pub)?;
            Ok(())
        })
        .unwrap();
    for peer in [r.id(), m.id(), r.id()] {
        let res = pool_m.authorize_peer(&peer, &send);
        assert!(
            matches!(
                res,
                Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
            ),
            "{res:?}"
        );
    }
    pool_m.close();
}

/// A warm link is closed once the root CRL becomes unresolvable: the member applies the root's
/// verified rotation, and its pool drops the slot instead of only refusing new decisions.
#[tokio::test]
async fn unresolvable_root_crl_closes_warm_links() {
    let mut b = Node::new(15).await;
    let mut c = Node::new(16).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let list = signed_list(&b.id(), 1, vec![], b.identity.signing_key());
    pin_root_with_list(&c, &b, &b.id(), list);
    let pool_b = b.serve(&gid);
    let pool_c = c.serve(&gid);
    let report = pool_b.broadcast(None, b"warm").await.unwrap();
    assert_eq!(report.delivered, vec![c.id()], "{report:?}");
    wait_until(|| pool_c.connected_peers().contains(&b.id())).await;

    let mut rotated = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41 + 15; 32]),
        SigningKeypair::from_seed([0x51 + 15; 32]),
    );
    rotated
        .rotate(
            StaticKeypair::from_scalar([0xD3; 32]),
            SigningKeypair::from_seed([0xD4; 32]),
            current_unix_secs(),
        )
        .unwrap();
    let new_pub = rotated.signing_key().public_key().clone();
    c.store
        .update_roster(|roster| {
            roster.apply_verified_rotation(
                &b.id(),
                rotated.rotation_chain(),
                rotated.static_key().public_bytes(),
                &new_pub,
            )?;
            Ok(())
        })
        .unwrap();
    wait_until(|| pool_c.connected_peers().is_empty()).await;
    let send = format!("group.send:{gid}");
    let res = pool_c.authorize_peer(&b.id(), &send);
    assert!(
        matches!(
            res,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{res:?}"
    );
    assert!(pool_c.connected_peers().is_empty());
    pool_b.close();
    pool_c.close();
}
