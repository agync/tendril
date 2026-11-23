//! Interleave tests that need the pool's test-only hooks.

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::group::GroupSeq;
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets, add_member,
    create_group, group_id_from_root, remove_member, renew_manifest, sign_group_manifest,
};
use tendril_core::identity::EndpointIdentity;
use tendril_core::policy::ProviderId;
use tendril_core::roster::{Roster, V2PeerSecrets};
use tendril_core::v2::PaddingPolicy;
use tokio::sync::oneshot;

use super::{GroupEvent, GroupHub, GroupPool, GroupPoolConfig, InboundSession};
use crate::driver::{SessionEvent, current_unix_secs};
use crate::error::RuntimeError;
use crate::provider::{PathDialer, PathListener, PathReader, PathStream, PathWriter};
use crate::providers::{DirectDialer, DirectListener};
use crate::store::StateStore;
use crate::v2_driver::{V2ResponderState, V2SessionDriver};

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

/// Counts the responder's transport writes.
struct CountingStream {
    inner: Box<dyn PathStream>,
    writes: Arc<AtomicUsize>,
}

struct CountingWriter {
    inner: Box<dyn PathWriter>,
    writes: Arc<AtomicUsize>,
}

#[async_trait]
impl PathWriter for CountingWriter {
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.writes.fetch_add(1, AtomicOrdering::SeqCst);
        self.inner.send_chunk(bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }
}

#[async_trait]
impl PathStream for CountingStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.writes.fetch_add(1, AtomicOrdering::SeqCst);
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let writes = self.writes;
        let (r, w) = self.inner.into_split();
        (r, Box::new(CountingWriter { inner: w, writes }))
    }
}

/// A raw Wire v2 sibling session from `b` into `pool_c.accept`.
struct Raw {
    driver: V2SessionDriver,
    roster: Roster,
    accept: tokio::task::JoinHandle<Result<String, RuntimeError>>,
    writes: Arc<AtomicUsize>,
}

/// `b`'s current `pair_bootstrap` with `c`.
fn bootstrap_of(b: &Node, c: &Node, gid: &str) -> V2PeerSecrets {
    let book = b.store.load_group_book().unwrap();
    super::bootstrap_secrets(&book, gid, &b.id(), &c.id(), current_unix_secs()).unwrap()
}

/// Dials a raw initiator from `b` with `secret` into `pool_c.accept` over a counted stream.
async fn raw_initiator(b: &Node, c: &Node, pool_c: &GroupPool, secret: &V2PeerSecrets) -> Raw {
    raw_initiator_over(b, c, pool_c, secret, |s| s).await
}

/// [`raw_initiator`] with the initiator's dialed stream wrapped by `wrap`.
async fn raw_initiator_over(
    b: &Node,
    c: &Node,
    pool_c: &GroupPool,
    secret: &V2PeerSecrets,
    wrap: impl FnOnce(Box<dyn PathStream>) -> Box<dyn PathStream>,
) -> Raw {
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let writes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&writes);
    let pool = pool_c.clone();
    let accept = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        pool.accept(Box::new(CountingStream {
            inner: stream,
            writes: counted,
        }))
        .await
    });
    let gid = pool_c.group_id().to_owned();
    let seq = pool_c.manifest().unwrap().seq;
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            c.id(),
            "sibling".into(),
            *c.identity.static_key().public_bytes(),
            None,
            0,
            vec![],
        )
        .unwrap();
    roster
        .pin_signing_hash(&c.id(), c.identity.signing_key().public_key().sha256_hash())
        .unwrap();
    roster.upgrade_peer_to_v2(&c.id(), secret.clone()).unwrap();
    let locked = Mutex::new(roster);
    let stream = wrap(DirectDialer::new().dial(&addr.to_string()).await.unwrap());
    let driver = V2SessionDriver::connect_group_member(
        stream,
        &b.identity,
        &c.id(),
        *secret.reconnect_secret(),
        PaddingPolicy::v2_default(),
        &locked,
        vec![GroupSeq { group_id: gid, seq }],
        current_unix_secs(),
    )
    .await
    .unwrap();
    Raw {
        driver,
        roster: locked.into_inner().unwrap(),
        accept,
        writes,
    }
}

/// Arms `gate`; returns its `reached` receiver and `release` sender.
fn arm_gate(gate: &super::TestGate) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (reached_tx, reached_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    *gate.lock().unwrap() = Some((reached_tx, release_rx));
    (reached_rx, release_tx)
}

fn gate_armed(gate: &super::TestGate) -> bool {
    gate.lock().unwrap().is_some()
}

async fn reached(rx: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("gate not reached")
        .unwrap();
}

async fn verdict(
    accept: tokio::task::JoinHandle<Result<String, RuntimeError>>,
) -> Result<String, RuntimeError> {
    tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("accept did not finish")
        .unwrap()
}

fn pairwise_of(node: &Node, gid: &str, peer: &Node) -> Option<V2PeerSecrets> {
    node.store
        .load_group_book()
        .unwrap()
        .pairwise_secrets(gid, &peer.id())
        .cloned()
}

fn permits_free(pool: &GroupPool) -> bool {
    pool.inner.pending_commits.available_permits() == super::MAX_PENDING_BOOTSTRAP_COMMITS
}

fn slot_initiator(pool: &GroupPool, peer: &Node) -> Option<String> {
    pool.inner
        .lock_state()
        .slots
        .get(&peer.id())
        .map(|l| l.initiator_id.clone())
}

/// A PING committing a bootstrap session: the responder writes nothing (no PONG) and persists
/// nothing until the commit; the PONG follows the install.
#[tokio::test]
async fn bootstrap_commit_on_ping_writes_nothing_before_persistence() {
    let b = Node::new(20).await;
    let c = Node::new(21).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (staged, release_staged) = arm_gate(&pool_c.inner.hooks.staged_inbound);
    let (committed, release_committed) = arm_gate(&pool_c.inner.hooks.committed_inbound);
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    reached(staged).await;
    let w0 = raw.writes.load(AtomicOrdering::SeqCst);
    release_staged.send(()).unwrap();
    raw.driver.send_ping(7).await.unwrap();
    reached(committed).await;
    assert_eq!(
        raw.writes.load(AtomicOrdering::SeqCst),
        w0,
        "wrote before commit"
    );
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    release_committed.send(()).unwrap();
    loop {
        let ev = tokio::time::timeout(
            Duration::from_secs(5),
            raw.driver.next_event(current_unix_secs(), &mut raw.roster),
        )
        .await
        .unwrap()
        .unwrap();
        match ev {
            Some(SessionEvent::PongReceived(7)) => break,
            Some(_) => {}
            None => panic!("closed before PONG"),
        }
    }
    assert_eq!(
        pairwise_of(&c, &gid, &b).as_ref(),
        raw.driver.exported_v2_secrets()
    );
    assert_eq!(verdict(raw.accept).await.unwrap(), b.id());
    pool_c.close();
}

/// An eventless cover frame commits.
#[tokio::test]
async fn bootstrap_commit_on_cover_frame() {
    let b = Node::new(22).await;
    let c = Node::new(23).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (committed, release) = arm_gate(&pool_c.inner.hooks.committed_inbound);
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    raw.driver.send_dummy_cover(256).await.unwrap();
    reached(committed).await;
    release.send(()).unwrap();
    assert_eq!(verdict(raw.accept).await.unwrap(), b.id());
    assert_eq!(
        pairwise_of(&c, &gid, &b).as_ref(),
        raw.driver.exported_v2_secrets()
    );
    pool_c.close();
}

/// The committing DATA frame is not lost: it is delivered after the install.
#[tokio::test]
async fn bootstrap_first_data_frame_is_delivered_after_commit() {
    let b = Node::new(24).await;
    let c = Node::new(25).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    raw.driver.send_data(b"first").await.unwrap();
    assert_eq!(verdict(raw.accept).await.unwrap(), b.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool_c.poll_event(left).await {
            Some(GroupEvent::AppData { payload, .. }) if payload == b"first" => break,
            Some(_) => {}
            None => panic!("first data frame lost"),
        }
    }
    pool_c.close();
}

/// CLOSE, EOF, or no frame within the commit timeout drop the session without persisting.
#[tokio::test]
async fn bootstrap_close_or_eof_before_commit_persists_nothing() {
    let b = Node::new(26).await;
    let c = Node::new(27).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let secret = bootstrap_of(&b, &c, &gid);
    for case in ["close", "eof", "timeout"] {
        let (_committed, _release) = arm_gate(&pool_c.inner.hooks.committed_inbound);
        if case == "timeout" {
            *pool_c.inner.hooks.commit_timeout.lock().unwrap() = Some(Duration::from_millis(50));
        }
        let mut raw = raw_initiator(&b, &c, &pool_c, &secret).await;
        let silent = match case {
            "close" => {
                raw.driver.send_close(1000, "bye").await.unwrap();
                None
            }
            "eof" => {
                drop(raw.driver);
                None
            }
            _ => Some(raw.driver),
        };
        let res = verdict(raw.accept).await;
        assert!(res.is_err(), "{case}: {res:?}");
        assert!(
            gate_armed(&pool_c.inner.hooks.committed_inbound),
            "{case}: committed"
        );
        assert_eq!(pairwise_of(&c, &gid, &b), None, "{case}");
        assert!(permits_free(&pool_c), "{case}");
        assert!(!pool_c.connected_peers().contains(&b.id()), "{case}");
        drop(silent);
    }
    pool_c.close();
}

/// Closing the pool cancels a session waiting for its commit frame.
#[tokio::test]
async fn close_cancels_a_pending_bootstrap_commit() {
    let b = Node::new(28).await;
    let c = Node::new(29).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (staged, release) = arm_gate(&pool_c.inner.hooks.staged_inbound);
    let raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    reached(staged).await;
    pool_c.close();
    release.send(()).unwrap();
    let res = verdict(raw.accept).await;
    assert!(matches!(res, Err(RuntimeError::Closed)), "{res:?}");
    assert!(permits_free(&pool_c));
    drop(raw.driver);
}

/// Bootstrap sessions over the pending cap are refused at once and persist nothing.
#[tokio::test]
async fn pending_bootstrap_commits_are_capped() {
    let b = Node::new(30).await;
    let c = Node::new(31).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let secret = bootstrap_of(&b, &c, &gid);
    let held = Arc::clone(&pool_c.inner.pending_commits)
        .try_acquire_many_owned(u32::try_from(super::MAX_PENDING_BOOTSTRAP_COMMITS).unwrap())
        .unwrap();
    let raw = raw_initiator(&b, &c, &pool_c, &secret).await;
    let res = verdict(raw.accept).await;
    assert!(matches!(res, Err(RuntimeError::RateLimited(_))), "{res:?}");
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    drop(held);
    let mut raw = raw_initiator(&b, &c, &pool_c, &secret).await;
    raw.driver.send_ping(1).await.unwrap();
    assert_eq!(verdict(raw.accept).await.unwrap(), b.id());
    assert_eq!(
        pairwise_of(&c, &gid, &b).as_ref(),
        raw.driver.exported_v2_secrets()
    );
    pool_c.close();
}

/// A rotation landing while a bootstrap session waits for its commit refuses it at the commit.
#[tokio::test]
async fn rotation_before_commit_refuses_the_staged_session() {
    let b = Node::new(32).await;
    let c = Node::new(33).await;
    let (gid, m2, s2) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (committed, release) = arm_gate(&pool_c.inner.hooks.committed_inbound);
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    raw.driver.send_ping(3).await.unwrap();
    reached(committed).await;
    let (m3, _) = renew_manifest(
        &m2,
        &GroupSigner::root(b.identity.signing_key()),
        &s2,
        GroupBuildParams::new(current_unix_secs()),
    )
    .unwrap();
    let s3 = V2GroupSecrets::generate(m3.seq).unwrap();
    store(&c, &m3, Some(&s3));
    release.send(()).unwrap();
    let res = verdict(raw.accept).await;
    assert!(
        matches!(
            res,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{res:?}"
    );
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    pool_c.close();
}

/// Close landing after the commit frame authenticated and before the install (close's flag
/// and slot drain run in that window) publishes and persists nothing.
#[tokio::test]
async fn close_after_the_commit_frame_publishes_and_persists_nothing() {
    let b = Node::new(60).await;
    let c = Node::new(61).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (committed, release) = arm_gate(&pool_c.inner.hooks.committed_inbound);
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    raw.driver.send_ping(5).await.unwrap();
    reached(committed).await;
    pool_c
        .inner
        .closed
        .store(true, std::sync::atomic::Ordering::Release);
    pool_c.disconnect_all();
    release.send(()).unwrap();
    let res = verdict(raw.accept).await;
    assert!(matches!(res, Err(RuntimeError::Closed)), "{res:?}");
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    assert!(pool_c.inner.lock_state().slots.is_empty());
    assert!(permits_free(&pool_c));
    pool_c.close();
}

/// A first REKEY commits; the DATA after it is delivered under the advanced receive key.
#[tokio::test]
async fn bootstrap_commit_on_rekey_then_data() {
    let b = Node::new(62).await;
    let c = Node::new(63).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (committed, release) = arm_gate(&pool_c.inner.hooks.committed_inbound);
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    raw.driver.send_rekey().await.unwrap();
    reached(committed).await;
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    release.send(()).unwrap();
    assert_eq!(verdict(raw.accept).await.unwrap(), b.id());
    raw.driver.send_data(b"after rekey").await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match pool_c.poll_event(left).await {
            Some(GroupEvent::AppData { payload, .. }) if payload == b"after rekey" => break,
            Some(_) => {}
            None => panic!("data after the committing rekey lost"),
        }
    }
    assert_eq!(
        pairwise_of(&c, &gid, &b).as_ref(),
        raw.driver.exported_v2_secrets()
    );
    pool_c.close();
}

/// Flips the last byte of every chunk written once `armed` is set.
struct TamperStream {
    inner: Box<dyn PathStream>,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl PathStream for TamperStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if !self.armed.load(AtomicOrdering::SeqCst) || bytes.is_empty() {
            return self.inner.send_chunk(bytes).await;
        }
        let mut tampered = bytes.to_vec();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x01;
        }
        self.inner.send_chunk(&tampered).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        self.inner.into_split()
    }
}

/// A first frame that fails authentication drops the session without persisting.
#[tokio::test]
async fn bootstrap_first_frame_failing_authentication_persists_nothing() {
    let b = Node::new(64).await;
    let c = Node::new(65).await;
    let (gid, _, _) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    *pool_c.inner.hooks.commit_timeout.lock().unwrap() = Some(Duration::from_secs(2));
    let (_committed, _release) = arm_gate(&pool_c.inner.hooks.committed_inbound);
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&armed);
    let raw = raw_initiator_over(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid), |s| {
        Box::new(TamperStream {
            inner: s,
            armed: flag,
        })
    })
    .await;
    let mut driver = raw.driver;
    armed.store(true, AtomicOrdering::SeqCst);
    driver.send_ping(9).await.unwrap();
    let res = verdict(raw.accept).await;
    assert!(res.is_err(), "{res:?}");
    assert!(gate_armed(&pool_c.inner.hooks.committed_inbound));
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    assert!(permits_free(&pool_c));
    pool_c.close();
}

/// A rotation landing between pairwise persistence and the second admission check, with the
/// membership unchanged, refuses the session and removes the secrets it persisted.
#[tokio::test]
async fn rotation_after_persistence_refuses_and_removes_the_secrets() {
    let b = Node::new(66).await;
    let c = Node::new(67).await;
    let (gid, m2, s2) = seed(&b, &[&c], 2);
    let pool_c = open_pool(&c, &gid);
    let (m3, _) = renew_manifest(
        &m2,
        &GroupSigner::root(b.identity.signing_key()),
        &s2,
        GroupBuildParams::new(current_unix_secs()),
    )
    .unwrap();
    let s3 = V2GroupSecrets::generate(m3.seq).unwrap();
    let c_store = c.store.clone();
    arm(&pool_c.inner.hooks.after_pairwise_persist, move || {
        c_store
            .update_group_book(|book| {
                book.ingest_group_manifest(&m3, current_unix_secs(), None)?;
                book.install_secrets(&m3.group_id, s3)?;
                Ok(())
            })
            .unwrap();
    });
    let mut raw = raw_initiator(&b, &c, &pool_c, &bootstrap_of(&b, &c, &gid)).await;
    raw.driver.send_ping(4).await.unwrap();
    let res = verdict(raw.accept).await;
    assert!(hook_fired(&pool_c.inner.hooks.after_pairwise_persist));
    assert!(
        matches!(
            res,
            Err(RuntimeError::Core(CoreError::GroupUnauthorized(_)))
        ),
        "{res:?}"
    );
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    assert!(pool_c.inner.lock_state().slots.is_empty());
    pool_c.close();
}

/// Both members dial each other on first contact: both ends keep the link whose initiator has
/// the smaller id and hold its secrets, so a later pairwise-only reconnect works.
#[tokio::test]
async fn simultaneous_first_contact_keeps_the_lower_initiator_link() {
    let mut b = Node::new(34).await;
    let mut c = Node::new(35).await;
    let (gid, m2, s2) = seed(&b, &[&c], 2);
    let pool_b = b.serve(&gid);
    let pool_c = c.serve(&gid);
    let (b_staged, b_release) = arm_gate(&pool_b.inner.hooks.staged_inbound);
    let (c_staged, c_release) = arm_gate(&pool_c.inner.hooks.staged_inbound);
    let (b_done, b_done_release) = arm_gate(&pool_b.inner.hooks.inbound_done);
    let (c_done, c_done_release) = arm_gate(&pool_c.inner.hooks.inbound_done);
    let sender_b = pool_b.clone();
    let sender_c = pool_c.clone();
    let from_b = tokio::spawn(async move { sender_b.broadcast(None, b"from-b").await });
    let from_c = tokio::spawn(async move { sender_c.broadcast(None, b"from-c").await });
    reached(b_staged).await;
    reached(c_staged).await;
    for (sent, peer) in [(from_b, c.id()), (from_c, b.id())] {
        let report = tokio::time::timeout(Duration::from_secs(10), sent)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(report.delivered, vec![peer], "{report:?}");
    }
    b_release.send(()).unwrap();
    c_release.send(()).unwrap();
    reached(b_done).await;
    reached(c_done).await;
    b_done_release.send(()).unwrap();
    c_done_release.send(()).unwrap();
    let lower = std::cmp::min(b.id(), c.id());
    wait_until(|| {
        slot_initiator(&pool_b, &c).as_deref() == Some(lower.as_str())
            && slot_initiator(&pool_c, &b).as_deref() == Some(lower.as_str())
    })
    .await;
    let pw = pairwise_of(&b, &gid, &c);
    assert!(pw.is_some());
    assert_eq!(pairwise_of(&c, &gid, &b), pw);

    let (m3, _) = renew_manifest(
        &m2,
        &GroupSigner::root(b.identity.signing_key()),
        &s2,
        GroupBuildParams::new(current_unix_secs()),
    )
    .unwrap();
    store(&b, &m3, None);
    store(&c, &m3, None);
    wait_until(|| {
        pool_b.manifest().unwrap().seq == m3.seq && pool_c.manifest().unwrap().seq == m3.seq
    })
    .await;
    pool_b.disconnect_all();
    pool_c.disconnect_all();
    let report = pool_b.broadcast(None, b"pairwise-only").await.unwrap();
    assert_eq!(report.delivered, vec![c.id()], "{report:?}");
    assert_eq!(pairwise_of(&b, &gid, &c), pw);
    assert_eq!(pairwise_of(&c, &gid, &b), pw);
    pool_b.close();
    pool_c.close();
}

/// One peer holding more than its share of pending commits is refused, while another
/// member's bootstrap session still commits.
#[tokio::test]
async fn one_peer_cannot_hold_every_pending_bootstrap_commit() {
    let b = Node::new(36).await;
    let c = Node::new(37).await;
    let d = Node::new(38).await;
    let (gid, _, _) = seed(&b, &[&c, &d], 2);
    let pool_c = open_pool(&c, &gid);
    let from_b = bootstrap_of(&b, &c, &gid);
    let mut silent = Vec::new();
    for _ in 0..super::MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER {
        silent.push(raw_initiator(&b, &c, &pool_c, &from_b).await);
    }
    wait_until(|| {
        pool_c.inner.pending_commits.available_permits()
            == super::MAX_PENDING_BOOTSTRAP_COMMITS - super::MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER
    })
    .await;
    let over = raw_initiator(&b, &c, &pool_c, &from_b).await;
    let res = verdict(over.accept).await;
    assert!(matches!(res, Err(RuntimeError::RateLimited(_))), "{res:?}");

    let mut other = raw_initiator(&d, &c, &pool_c, &bootstrap_of(&d, &c, &gid)).await;
    other.driver.send_ping(9).await.unwrap();
    assert_eq!(verdict(other.accept).await.unwrap(), d.id());
    assert_eq!(
        pairwise_of(&c, &gid, &d).as_ref(),
        other.driver.exported_v2_secrets()
    );
    assert_eq!(pairwise_of(&c, &gid, &b), None);
    drop(silent);
    pool_c.close();
}
