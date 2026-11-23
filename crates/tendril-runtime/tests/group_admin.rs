//! Group admin facade: create, add, remove, ingest, and forget policy.

use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets, add_member,
    create_group, decode_group_rendezvous_frame, encode_group_rendezvous_frame, group_id_from_root,
    issue_admin_grant, remove_member, renew_manifest,
};
use tendril_core::identity::EndpointIdentity;
use tendril_core::roster::V2PeerSecrets;
use tendril_runtime::{
    MAX_GROUPS_PER_SIGNER, MAX_LOCAL_GROUPS, MAX_STORED_GROUPS, RuntimeError, StateStore,
    default_group_caps, group_add_member, group_create, group_forget, group_ingest_manifest,
    group_remove_member, ingest_pushed_manifest, ingest_pushed_rendezvous,
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
    identity: EndpointIdentity,
}

fn node(n: u8) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open_or_create(dir.path()).unwrap();
    let identity = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41 + n; 32]),
        SigningKeypair::from_seed([0x51 + n; 32]),
    );
    Node {
        _dir: dir,
        store,
        identity,
    }
}

impl Node {
    fn id(&self) -> String {
        self.identity.device_id()
    }

    fn member(&self, name: &str, gid: &str) -> GroupMember {
        GroupMember::new(
            self.identity.static_key().public_bytes(),
            name,
            self.identity.signing_key().public_key(),
            vec![],
            default_group_caps(gid),
        )
    }
}

/// `a` knows `x` as an active paired peer.
fn pair(a: &Node, x: &Node, with_signing_key: bool) {
    a.store
        .update_roster(|r| {
            r.record_pending_pair(
                *x.identity.static_key().public_bytes(),
                with_signing_key.then(|| x.identity.signing_key().public_key().clone()),
                "peer".into(),
                "peer".into(),
                "1111".into(),
            )?;
            r.confirm_peer(&x.id(), Some("1111"))?;
            Ok(())
        })
        .unwrap();
}

/// `x` pins `a` as the paired peer that may push first-contact manifests.
fn pin_host(x: &Node, a: &Node) {
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
            Ok(())
        })
        .unwrap();
}

fn is_unauthorized<T: std::fmt::Debug>(r: &Result<T, RuntimeError>) -> bool {
    matches!(r, Err(RuntimeError::Core(CoreError::GroupUnauthorized(_))))
}

/// A group rooted at an unrelated key with `member` as an ordinary member.
fn foreign_group(seed: u8, member: &Node) -> (GroupManifest, V2GroupSecrets, SigningKeypair) {
    let key = SigningKeypair::from_seed([seed; 32]);
    let gid = group_id_from_root(key.public_key());
    let root = GroupMember::new(
        StaticKeypair::from_scalar([seed; 32]).public_bytes(),
        "root",
        key.public_key(),
        vec![],
        default_group_caps(&gid),
    );
    let params = GroupBuildParams::new(now());
    let (m, s) = create_group(&key, "foreign", 1, root, params).unwrap();
    let (m, s) = add_member(
        &m,
        &GroupSigner::root(&key),
        member.member("m", &gid),
        &s,
        params,
    )
    .unwrap();
    (m, s, key)
}

fn store_group(node: &Node, manifest: &GroupManifest, secrets: Option<&V2GroupSecrets>) {
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

fn fill_as_member(node: &Node) -> Vec<(GroupManifest, V2GroupSecrets, SigningKeypair)> {
    (0..u8::try_from(MAX_LOCAL_GROUPS).unwrap())
        .map(|i| {
            let g = foreign_group(0xB0 + i, node);
            store_group(node, &g.0, None);
            g
        })
        .collect()
}

#[test]
fn create_add_remove_happy_path_persists_each_step() {
    let a = node(0);
    let b = node(1);
    pair(&a, &b, true);

    let m1 = group_create(
        &a.store,
        &a.identity,
        "team",
        2,
        vec!["127.0.0.1:9".into(), "direct:127.0.0.2:9".into()],
    )
    .unwrap();
    let gid = m1.group_id.clone();
    assert_eq!(m1.min_wire_version, 2);
    assert_eq!(
        m1.members[0].endpoints,
        vec!["direct:127.0.0.1:9", "direct:127.0.0.2:9"]
    );
    let book = a.store.load_group_book().unwrap();
    assert_eq!(book.manifest(&gid).unwrap().seq, m1.seq);
    assert!(book.secrets(&gid).is_some());

    let m2 = group_add_member(&a.store, &a.identity, &gid, &b.id(), vec![], vec![]).unwrap();
    assert!(m2.seq > m1.seq);
    let added = m2.members.iter().find(|m| m.device_id == b.id()).unwrap();
    assert_eq!(added.caps, default_group_caps(&gid));

    let m3 = group_remove_member(&a.store, &a.identity, &gid, &b.id()).unwrap();
    assert!(m3.revoked_members.contains(&b.id()));
    let book = a.store.load_group_book().unwrap();
    assert_eq!(book.manifest(&gid).unwrap().seq, m3.seq);
    assert_eq!(book.secrets(&gid).unwrap().seq(), m3.seq);
}

#[test]
fn explicit_caps_replace_the_default() {
    let a = node(0);
    let b = node(1);
    pair(&a, &b, true);
    let gid = group_create(&a.store, &a.identity, "t", 1, vec![])
        .unwrap()
        .group_id;
    let cap = format!("group.recv:{gid}");
    let m = group_add_member(
        &a.store,
        &a.identity,
        &gid,
        &b.id(),
        vec![cap.clone()],
        vec![],
    )
    .unwrap();
    let added = m.members.iter().find(|x| x.device_id == b.id()).unwrap();
    assert_eq!(added.caps, vec![cap]);
}

#[test]
fn duplicate_create_is_refused_and_leaves_the_group_untouched() {
    let a = node(0);
    let first = group_create(&a.store, &a.identity, "t", 1, vec![]).unwrap();
    let again = group_create(&a.store, &a.identity, "t2", 1, vec![]);
    assert!(is_unauthorized(&again), "{again:?}");
    let book = a.store.load_group_book().unwrap();
    assert_eq!(book.group_ids(), vec![first.group_id.clone()]);
    assert_eq!(book.manifest(&first.group_id).unwrap().name, "t");
}

#[test]
fn create_is_refused_at_the_local_group_cap() {
    let a = node(0);
    fill_as_member(&a);
    let refused = group_create(&a.store, &a.identity, "t", 1, vec![]);
    assert!(is_unauthorized(&refused), "{refused:?}");
    assert_eq!(
        a.store.load_group_book().unwrap().group_ids().len(),
        MAX_LOCAL_GROUPS
    );
}

#[test]
fn add_refuses_unknown_pending_unkeyed_and_crl_revoked_peers() {
    let a = node(0);
    let b = node(1);
    let c = node(2);
    let d = node(3);
    let gid = group_create(&a.store, &a.identity, "t", 1, vec![])
        .unwrap()
        .group_id;
    let add =
        |peer: &Node| group_add_member(&a.store, &a.identity, &gid, &peer.id(), vec![], vec![]);

    let r = add(&b);
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::PeerNotFound(_)))),
        "{r:?}"
    );

    a.store
        .update_roster(|r| {
            r.record_pending_pair(
                *b.identity.static_key().public_bytes(),
                Some(b.identity.signing_key().public_key().clone()),
                "peer".into(),
                "peer".into(),
                "1111".into(),
            )?;
            Ok(())
        })
        .unwrap();
    let r = add(&b);
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::PeerPending(_)))),
        "{r:?}"
    );

    pair(&a, &c, false);
    let r = add(&c);
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::IncompletePin(_)))),
        "{r:?}"
    );

    pair(&a, &d, true);
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: a.id(),
            seq: 1,
            revoked_devices: vec![d.id()],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        a.identity.signing_key(),
    )
    .unwrap();
    let a_pub = a.identity.signing_key().public_key().clone();
    a.store
        .update_roster(|r| r.ingest_crl(crl, &a.id(), &a_pub).map_err(Into::into))
        .unwrap();
    let r = add(&d);
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::PeerRevoked(_)))),
        "{r:?}"
    );

    let book = a.store.load_group_book().unwrap();
    assert_eq!(book.manifest(&gid).unwrap().members.len(), 1);
}

/// `a` pins `x` under the host `label` (with its signing key when `label_signing`) and records
/// the reverse pairing as a `dev_` entry, keyed when `dev_signing` and confirmed when `confirm`.
fn reverse_pair(
    a: &Node,
    x: &Node,
    label: &str,
    label_signing: bool,
    dev_signing: bool,
    confirm: bool,
) {
    a.store
        .update_roster(|r| {
            r.record_pending_pair(
                *x.identity.static_key().public_bytes(),
                dev_signing.then(|| x.identity.signing_key().public_key().clone()),
                "peer".into(),
                "peer".into(),
                "1111".into(),
            )?;
            if confirm {
                r.confirm_peer(&x.id(), Some("1111"))?;
            }
            r.insert_pinned_host(
                label.into(),
                "peer".into(),
                *x.identity.static_key().public_bytes(),
                label_signing.then(|| x.identity.signing_key().public_key().clone()),
                0,
                vec![],
            )?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn add_selects_the_usable_entry_of_a_reverse_paired_peer() {
    for label in ["a-host", "z-host"] {
        for (dev_signing, confirm) in [(true, false), (false, true)] {
            let a = node(0);
            let b = node(1);
            let gid = group_create(&a.store, &a.identity, "t", 1, vec![])
                .unwrap()
                .group_id;
            reverse_pair(&a, &b, label, true, dev_signing, confirm);
            let m = group_add_member(&a.store, &a.identity, &gid, &b.id(), vec![], vec![])
                .unwrap_or_else(|e| panic!("{label} dev_signing={dev_signing}: {e:?}"));
            let added = m.members.iter().find(|x| x.device_id == b.id()).unwrap();
            assert_eq!(added, &b.member("peer", &gid));
        }
    }
}

#[test]
fn add_refuses_a_peer_with_any_crl_revoked_alias() {
    for label in ["a-host", "z-host"] {
        let a = node(0);
        let b = node(1);
        let gid = group_create(&a.store, &a.identity, "t", 1, vec![])
            .unwrap()
            .group_id;
        reverse_pair(&a, &b, label, true, true, true);
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: a.id(),
                seq: 1,
                revoked_devices: vec![label.to_owned()],
                revoked_nonces: vec![],
                ts: "2026-11-22T00:00:00Z".to_owned(),
            },
            a.identity.signing_key(),
        )
        .unwrap();
        let a_pub = a.identity.signing_key().public_key().clone();
        a.store
            .update_roster(|r| r.ingest_crl(crl, &a.id(), &a_pub).map_err(Into::into))
            .unwrap();
        let r = group_add_member(&a.store, &a.identity, &gid, &b.id(), vec![], vec![]);
        assert!(
            matches!(r, Err(RuntimeError::Core(CoreError::PeerRevoked(_)))),
            "{label}: {r:?}"
        );
    }
}

#[test]
fn non_root_cannot_add_or_remove_and_unknown_groups_are_not_found() {
    let a = node(0);
    let b = node(1);
    let c = node(2);
    let (m, s, _key) = foreign_group(0xE0, &b);
    store_group(&b, &m, Some(&s));
    pair(&b, &c, true);

    let r = group_add_member(&b.store, &b.identity, &m.group_id, &c.id(), vec![], vec![]);
    assert!(is_unauthorized(&r), "{r:?}");
    let r = group_remove_member(&b.store, &b.identity, &m.group_id, &b.id());
    assert!(is_unauthorized(&r), "{r:?}");
    assert_eq!(
        b.store
            .load_group_book()
            .unwrap()
            .manifest(&m.group_id)
            .unwrap()
            .seq,
        m.seq
    );

    let r = group_remove_member(&a.store, &a.identity, "nope", &b.id());
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::GroupNotFound(_)))),
        "{r:?}"
    );
}

#[test]
fn ingest_parses_strictly_then_applies_first_contact_rules() {
    let a = node(0);
    let b = node(1);
    let c = node(2);
    pair(&b, &a, true);
    pin_host(&b, &a);
    let m = group_create(&a.store, &a.identity, "t", 1, vec![]).unwrap();
    pair(&a, &b, true);
    let m = group_add_member(&a.store, &a.identity, &m.group_id, &b.id(), vec![], vec![]).unwrap();
    let json = serde_json::to_string(&m).unwrap();

    let r = group_ingest_manifest(&b.store, &b.id(), &a.id(), "{not json");
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::Json(_)))),
        "{r:?}"
    );
    let mut extra: serde_json::Value = serde_json::from_str(&json).unwrap();
    extra["surprise"] = serde_json::json!(1);
    let r = group_ingest_manifest(&b.store, &b.id(), &a.id(), &extra.to_string());
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::Json(_)))),
        "{r:?}"
    );

    // An unpaired sender is not a valid first contact.
    let r = group_ingest_manifest(&b.store, &b.id(), &c.id(), &json);
    assert!(is_unauthorized(&r), "{r:?}");
    assert!(b.store.load_group_book().unwrap().group_ids().is_empty());

    let out = group_ingest_manifest(&b.store, &b.id(), &a.id(), &json).unwrap();
    assert_eq!(out.group_id, m.group_id);
    assert_eq!(out.seq, m.seq);
    assert!(
        b.store
            .load_group_book()
            .unwrap()
            .manifest(&m.group_id)
            .is_some()
    );
}

#[test]
fn revoked_groups_free_their_slots_for_new_first_contact() {
    let a = node(0);
    let b = node(1);
    pair(&b, &a, true);
    pin_host(&b, &a);
    let groups = fill_as_member(&b);

    let new = group_create(&a.store, &a.identity, "new", 1, vec![]).unwrap();
    pair(&a, &b, true);
    let new = group_add_member(
        &a.store,
        &a.identity,
        &new.group_id,
        &b.id(),
        vec![],
        vec![],
    )
    .unwrap();
    let json = serde_json::to_string(&new).unwrap();

    // Full of active memberships: refused.
    let r = group_ingest_manifest(&b.store, &b.id(), &a.id(), &json);
    assert!(is_unauthorized(&r), "{r:?}");

    // Revoked from every one of them: the slots are free again.
    for (m, s, key) in &groups {
        let (revoked, _) = remove_member(
            m,
            &GroupSigner::root(key),
            &b.id(),
            s,
            GroupBuildParams::new(now()),
        )
        .unwrap();
        store_group(&b, &revoked, None);
    }
    assert_eq!(
        b.store.load_group_book().unwrap().group_ids().len(),
        MAX_LOCAL_GROUPS
    );
    group_ingest_manifest(&b.store, &b.id(), &a.id(), &json).unwrap();
    assert!(
        b.store
            .load_group_book()
            .unwrap()
            .manifest(&new.group_id)
            .is_some()
    );
}

#[test]
fn forget_clears_all_secret_material_and_refuses_the_root() {
    let a = node(0);
    let b = node(1);
    let (m, s, _key) = foreign_group(0xE1, &b);
    store_group(&b, &m, Some(&s));
    let gid = m.group_id.clone();
    b.store
        .update_group_book(|book| {
            book.set_pairwise_secrets(&gid, &b.id(), V2PeerSecrets::new([1; 32], [2; 32]))?;
            Ok(())
        })
        .unwrap();
    let book = b.store.load_group_book().unwrap();
    assert!(book.secrets(&gid).is_some());
    assert!(book.pairwise_secrets(&gid, &b.id()).is_some());

    group_forget(&b.store, &b.id(), &gid).unwrap();
    let book = b.store.load_group_book().unwrap();
    assert!(book.manifest(&gid).is_none());
    assert!(book.secrets(&gid).is_none());
    assert!(book.pairwise_secrets(&gid, &b.id()).is_none());
    assert!(book.root_signing_pub(&gid).is_none());
    assert!(book.group_ids().is_empty());

    let r = group_forget(&b.store, &b.id(), &gid);
    assert!(
        matches!(r, Err(RuntimeError::Core(CoreError::GroupNotFound(_)))),
        "{r:?}"
    );

    let own = group_create(&a.store, &a.identity, "t", 1, vec![]).unwrap();
    let r = group_forget(&a.store, &a.id(), &own.group_id);
    assert!(is_unauthorized(&r), "{r:?}");
    assert!(
        a.store
            .load_group_book()
            .unwrap()
            .secrets(&own.group_id)
            .is_some()
    );
}

#[test]
fn removal_drops_secrets_but_keeps_seq_and_fork_rules() {
    let b = node(1);
    let (m, s, key) = foreign_group(0xE2, &b);
    store_group(&b, &m, Some(&s));
    let gid = m.group_id.clone();
    b.store
        .update_group_book(|book| {
            book.set_pairwise_secrets(&gid, &b.id(), V2PeerSecrets::new([1; 32], [2; 32]))?;
            Ok(())
        })
        .unwrap();

    let (removed, _) = remove_member(
        &m,
        &GroupSigner::root(&key),
        &b.id(),
        &s,
        GroupBuildParams::new(now()),
    )
    .unwrap();
    let root_id = removed.signer_device_id.clone();
    ingest_pushed_manifest(&b.store, &b.id(), &root_id, &removed).unwrap();

    let book = b.store.load_group_book().unwrap();
    assert!(book.secrets(&gid).is_none());
    assert!(book.pairwise_secrets(&gid, &b.id()).is_none());
    assert_eq!(book.manifest(&gid).unwrap().seq, removed.seq);

    // Rollback to the earlier seq is still refused after the secrets are gone.
    let r = ingest_pushed_manifest(&b.store, &b.id(), &root_id, &m);
    assert!(
        matches!(
            r,
            Err(RuntimeError::Core(CoreError::GroupSeqRollback { .. }))
        ),
        "{r:?}"
    );
    // The same manifest again is an idempotent no-op.
    ingest_pushed_manifest(&b.store, &b.id(), &root_id, &removed).unwrap();
}

#[test]
fn stored_group_records_are_capped_and_forget_frees_a_slot() {
    let a = node(0);
    let b = node(1);
    pair(&b, &a, true);
    pin_host(&b, &a);
    let total = u8::try_from(MAX_STORED_GROUPS).unwrap();
    let mut groups = Vec::new();
    for i in 0..total {
        let g = foreign_group(0x80 + i, &b);
        store_group(&b, &g.0, None);
        groups.push(g);
    }
    // Remove the local device from all but one so the active-member cap is not the limit.
    for (m, s, key) in groups.iter().skip(1) {
        let (revoked, _) = remove_member(
            m,
            &GroupSigner::root(key),
            &b.id(),
            s,
            GroupBuildParams::new(now()),
        )
        .unwrap();
        store_group(&b, &revoked, None);
    }
    assert_eq!(
        b.store.load_group_book().unwrap().group_ids().len(),
        MAX_STORED_GROUPS
    );

    let new = group_create(&a.store, &a.identity, "new", 1, vec![]).unwrap();
    pair(&a, &b, true);
    let new = group_add_member(
        &a.store,
        &a.identity,
        &new.group_id,
        &b.id(),
        vec![],
        vec![],
    )
    .unwrap();
    let json = serde_json::to_string(&new).unwrap();

    let r = group_ingest_manifest(&b.store, &b.id(), &a.id(), &json);
    assert!(is_unauthorized(&r), "{r:?}");
    assert!(
        b.store
            .load_group_book()
            .unwrap()
            .manifest(&new.group_id)
            .is_none()
    );

    group_forget(&b.store, &b.id(), &groups[1].0.group_id).unwrap();
    group_ingest_manifest(&b.store, &b.id(), &a.id(), &json).unwrap();
    assert_eq!(
        b.store.load_group_book().unwrap().group_ids().len(),
        MAX_STORED_GROUPS
    );
}

#[test]
fn facade_refuses_an_identity_whose_host_id_differs_from_device_id() {
    let a = node(0);
    let bad = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x77; 32]),
        SigningKeypair::from_seed([0x78; 32]),
    )
    .with_host_id("not-the-device-id");
    assert_ne!(bad.host_id(), bad.device_id());

    let r = group_create(&a.store, &bad, "t", 1, vec![]);
    assert!(is_unauthorized(&r), "{r:?}");
    let r = group_add_member(
        &a.store,
        &bad,
        "grp_0000000000000000",
        "dev_x",
        vec![],
        vec![],
    );
    assert!(is_unauthorized(&r), "{r:?}");
    let r = group_remove_member(&a.store, &bad, "grp_0000000000000000", "dev_x");
    assert!(is_unauthorized(&r), "{r:?}");
    assert!(a.store.load_group_book().unwrap().group_ids().is_empty());
}

#[test]
fn removed_device_refuses_a_pushed_rendezvous_frame() {
    let b = node(1);
    let (m, s, key) = foreign_group(0xE3, &b);
    store_group(&b, &m, Some(&s));
    let gid = m.group_id.clone();
    let (removed, next) = remove_member(
        &m,
        &GroupSigner::root(&key),
        &b.id(),
        &s,
        GroupBuildParams::new(now()),
    )
    .unwrap();
    let root_id = removed.signer_device_id.clone();
    ingest_pushed_manifest(&b.store, &b.id(), &root_id, &removed).unwrap();
    assert!(b.store.load_group_book().unwrap().secrets(&gid).is_none());

    let payload =
        encode_group_rendezvous_frame(&gid, next.seq(), next.group_rendezvous_key()).unwrap();
    let frame = decode_group_rendezvous_frame(&payload[..]).unwrap();
    let r = ingest_pushed_rendezvous(&b.store, &b.id(), &root_id, &frame);
    assert!(is_unauthorized(&r), "{r:?}");
    assert!(b.store.load_group_book().unwrap().secrets(&gid).is_none());
}

fn root_signed_list(issuer: &str, revoked: Vec<String>, key: &SigningKeypair) -> RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: issuer.to_owned(),
            seq: 1,
            revoked_devices: revoked,
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".to_owned(),
        },
        key,
    )
    .unwrap()
}

/// How the member `b` knows the root's revocation list.
enum RootList {
    HostLabel(Vec<String>),
    RotatedAtDeviceId,
}

/// A root CRL stored under a host label revokes a co-admin for pushed manifests and keys,
/// and a rotated root keyed by its device id fails both closed.
#[test]
fn host_labeled_root_crl_blocks_a_revoked_co_admin() {
    let a = node(0);
    let c = node(2);
    let params = GroupBuildParams::new(now());
    let root_pub = a.identity.signing_key().public_key().clone();
    let gid = group_id_from_root(&root_pub);
    let (m, s) = create_group(
        a.identity.signing_key(),
        "t",
        1,
        a.member("root", &gid),
        params,
    )
    .unwrap();
    let root = GroupSigner::root(a.identity.signing_key());
    let local = node(1);
    let (m, s) = add_member(&m, &root, local.member("b", &gid), &s, params).unwrap();
    let (m2, s2) = add_member(&m, &root, c.member("c", &gid), &s, params).unwrap();
    let grant = issue_admin_grant(
        a.identity.signing_key(),
        &a.id(),
        &gid,
        &c.id(),
        c.identity.signing_key().public_key(),
        0,
        params,
    )
    .unwrap();
    let co = GroupSigner::co_admin(c.identity.signing_key(), c.id(), grant);
    let (m3, s3) = renew_manifest(&m2, &co, &s2, params).unwrap();
    let payload = encode_group_rendezvous_frame(&gid, s3.seq(), s3.group_rendezvous_key()).unwrap();
    let frame = decode_group_rendezvous_frame(&payload[..]).unwrap();

    let attempt = |list: RootList| {
        // `b` holds the root-signed manifest; `k` already holds the co-admin manifest.
        let b = node(1);
        let k = node(1);
        store_group(&b, &m2, None);
        store_group(&k, &m3, None);
        for x in [&b, &k] {
            x.store
                .update_roster(|r| {
                    match &list {
                        RootList::HostLabel(revoked) => {
                            r.insert_pinned_host(
                                "root-host".into(),
                                "root".into(),
                                *a.identity.static_key().public_bytes(),
                                Some(root_pub.clone()),
                                0,
                                vec![],
                            )?;
                            let crl = root_signed_list(
                                "root-host",
                                revoked.clone(),
                                a.identity.signing_key(),
                            );
                            r.ingest_crl(crl, "root-host", &root_pub)?;
                        }
                        RootList::RotatedAtDeviceId => {
                            r.insert_pinned_host(
                                a.id(),
                                "root".into(),
                                *a.identity.static_key().public_bytes(),
                                Some(root_pub.clone()),
                                0,
                                vec![],
                            )?;
                            let mut rotated = node(0).identity;
                            rotated.rotate(
                                StaticKeypair::from_scalar([0xD5; 32]),
                                SigningKeypair::from_seed([0xD6; 32]),
                                now(),
                            )?;
                            let new_pub = rotated.signing_key().public_key().clone();
                            r.apply_verified_rotation(
                                &a.id(),
                                rotated.rotation_chain(),
                                rotated.static_key().public_bytes(),
                                &new_pub,
                            )?;
                            let crl = root_signed_list(&a.id(), vec![], rotated.signing_key());
                            r.ingest_crl(crl, &a.id(), &new_pub)?;
                        }
                    }
                    Ok(())
                })
                .unwrap();
        }
        let pushed = ingest_pushed_manifest(&b.store, &b.id(), &c.id(), &m3).map(|_| ());
        let keyed = ingest_pushed_rendezvous(&k.store, &k.id(), &c.id(), &frame);
        (pushed, keyed)
    };

    let (pushed, keyed) = attempt(RootList::HostLabel(vec![c.id()]));
    assert!(is_unauthorized(&pushed), "{pushed:?}");
    assert!(is_unauthorized(&keyed), "{keyed:?}");
    let (pushed, keyed) = attempt(RootList::HostLabel(vec![]));
    pushed.unwrap();
    keyed.unwrap();
    let (pushed, keyed) = attempt(RootList::RotatedAtDeviceId);
    assert!(is_unauthorized(&pushed), "{pushed:?}");
    assert!(is_unauthorized(&keyed), "{keyed:?}");
}

/// A group rooted at an unrelated key (`seed`) in which `admin` is a co-admin that signed the
/// manifest adding `member`.
fn co_admin_group(seed: u8, admin: &Node, member: &Node) -> GroupManifest {
    let key = SigningKeypair::from_seed([seed; 32]);
    let gid = group_id_from_root(key.public_key());
    let root = GroupMember::new(
        StaticKeypair::from_scalar([seed; 32]).public_bytes(),
        "root",
        key.public_key(),
        vec![],
        default_group_caps(&gid),
    );
    let root_id = root.device_id.clone();
    let params = GroupBuildParams::new(now());
    let (m, s) = create_group(&key, "co", 1, root, params).unwrap();
    let (m, s) = add_member(
        &m,
        &GroupSigner::root(&key),
        admin.member("admin", &gid),
        &s,
        params,
    )
    .unwrap();
    let grant = issue_admin_grant(
        &key,
        &root_id,
        &gid,
        &admin.id(),
        admin.identity.signing_key().public_key(),
        0,
        params,
    )
    .unwrap();
    let co = GroupSigner::co_admin(admin.identity.signing_key(), admin.id(), grant);
    add_member(&m, &co, member.member("m", &gid), &s, params)
        .unwrap()
        .0
}

/// First-contact pins pushed by one paired peer are capped; another peer has its own quota.
#[test]
fn first_contact_quota_applies_per_paired_peer() {
    let a = node(0);
    let b = node(1);
    let c = node(2);
    pair(&b, &a, true);
    pair(&b, &c, true);
    let total = u8::try_from(MAX_GROUPS_PER_SIGNER).unwrap() + 1;
    for i in 0..total {
        let m = co_admin_group(0x30 + i, &a, &b);
        let json = serde_json::to_string(&m).unwrap();
        let r = group_ingest_manifest(&b.store, &b.id(), &a.id(), &json);
        let stored = b
            .store
            .load_group_book()
            .unwrap()
            .manifest(&m.group_id)
            .is_some();
        if i + 1 < total {
            r.unwrap();
            assert!(stored);
        } else {
            assert!(is_unauthorized(&r), "{r:?}");
            assert!(!stored);
        }
    }
    let m = co_admin_group(0x40, &c, &b);
    let json = serde_json::to_string(&m).unwrap();
    group_ingest_manifest(&b.store, &b.id(), &c.id(), &json).unwrap();
    assert_eq!(
        b.store.load_group_book().unwrap().group_ids().len(),
        MAX_GROUPS_PER_SIGNER + 1
    );
}
