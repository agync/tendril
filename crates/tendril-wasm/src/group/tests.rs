use tendril_core::crypto::b64url_encode;
use tendril_core::grants::{RevocationListUnsigned, sign_crl};
use tendril_core::group::{
    GroupBuildParams, GroupMember, GroupSigner, V2GroupSecrets, add_member, create_group,
    decode_group_rendezvous_frame, encode_group_rendezvous_frame, issue_admin_grant, remove_member,
};
use tendril_core::identity::EndpointIdentity;

use super::*;
use crate::WasmIdentity;

const NOW: u64 = 1_795_564_800;
const CRL_TS: &str = "2026-11-25T00:00:00Z";

struct Actor {
    id: EndpointIdentity,
}

impl Actor {
    fn new(host_id: &str) -> Self {
        Self {
            id: EndpointIdentity::generate().unwrap().with_host_id(host_id),
        }
    }

    fn device_id(&self) -> String {
        self.id.device_id()
    }

    fn member(&self, caps: Vec<String>) -> GroupMember {
        GroupMember::new(
            self.id.static_key().public_bytes(),
            self.id.host_id(),
            self.id.signing_key().public_key(),
            Vec::new(),
            caps,
        )
    }
}

fn caps(gid: &str) -> Vec<String> {
    vec![format!("group.send:{gid}"), format!("group.recv:{gid}")]
}

fn pin(roster: &mut Roster, peer: &Actor) {
    roster
        .insert_pinned_host(
            peer.id.host_id().to_owned(),
            peer.id.host_id().to_owned(),
            *peer.id.static_key().public_bytes(),
            Some(peer.id.signing_key().public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
}

struct Mesh {
    root: Actor,
    local: Actor,
    sibling: Actor,
    group_id: String,
    manifest: GroupManifest,
    secrets: V2GroupSecrets,
}

fn mesh() -> Mesh {
    let root = Actor::new("root-host");
    let local = Actor::new("web-host");
    let sibling = Actor::new("sibling-host");
    let params = GroupBuildParams::new(NOW);
    let (m1, s1) = create_group(
        root.id.signing_key(),
        "mesh",
        1,
        root.member(Vec::new()),
        params,
    )
    .unwrap();
    let gid = m1.group_id.clone();
    let signer = GroupSigner::root(root.id.signing_key());
    let (m2, s2) = add_member(&m1, &signer, local.member(caps(&gid)), &s1, params).unwrap();
    let (m3, s3) = add_member(&m2, &signer, sibling.member(caps(&gid)), &s2, params).unwrap();
    Mesh {
        root,
        local,
        sibling,
        group_id: gid,
        manifest: m3,
        secrets: s3,
    }
}

fn local_book(m: &Mesh) -> WasmGroupBook {
    WasmGroupBook::from_parts(m.local.device_id(), GroupBook::new())
}

fn roster_with_root(m: &Mesh) -> Roster {
    let mut roster = Roster::new();
    pin(&mut roster, &m.root);
    roster
}

fn pinned(m: &Mesh) -> (WasmGroupBook, Roster) {
    let roster = roster_with_root(m);
    let mut book = local_book(m);
    book.ingest_manifest_inner(&roster, &m.root.device_id(), &m.manifest, NOW)
        .unwrap();
    (book, roster)
}

fn revoke_sibling(m: &Mesh) -> GroupManifest {
    let signer = GroupSigner::root(m.root.id.signing_key());
    remove_member(
        &m.manifest,
        &signer,
        &m.sibling.device_id(),
        &m.secrets,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap()
    .0
}

#[test]
fn first_contact_pins_only_from_signer_peer() {
    let m = mesh();
    let roster = roster_with_root(&m);
    let root_id = m.root.device_id();

    let mut book = local_book(&m);
    let out = book
        .ingest_manifest_inner(&roster, &root_id, &m.manifest, NOW)
        .unwrap();
    assert_eq!(out.status, GroupIngestStatus::Created);
    assert_eq!(book.inner.group_ids(), vec![m.group_id.clone()]);
}

#[test]
fn first_contact_refuses_member_that_is_not_the_signer() {
    let m = mesh();
    let mut roster = roster_with_root(&m);
    pin(&mut roster, &m.sibling);
    let mut book = local_book(&m);
    let err = book
        .ingest_manifest_inner(&roster, &m.sibling.device_id(), &m.manifest, NOW)
        .unwrap_err();
    assert!(err.contains("manifest signer"), "{err}");
    assert!(book.inner.group_ids().is_empty());
}

#[test]
fn first_contact_refuses_unpaired_signer_and_wrong_pin() {
    let m = mesh();
    let mut book = local_book(&m);
    let err = book
        .ingest_manifest_inner(&Roster::new(), &m.root.device_id(), &m.manifest, NOW)
        .unwrap_err();
    assert!(err.contains("not an active paired peer"), "{err}");

    let mut other_pin = Roster::new();
    let impostor = Actor::new("root-host");
    other_pin
        .insert_pinned_host(
            "root-host".to_owned(),
            "root-host".to_owned(),
            *m.root.id.static_key().public_bytes(),
            Some(impostor.id.signing_key().public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    let err = book
        .ingest_manifest_inner(&other_pin, &m.root.device_id(), &m.manifest, NOW)
        .unwrap_err();
    assert!(err.contains("differs from the paired peer"), "{err}");
    assert!(book.inner.group_ids().is_empty());
}

#[test]
fn first_contact_refuses_when_local_is_not_a_member() {
    let m = mesh();
    let roster = roster_with_root(&m);
    let outsider = Actor::new("outsider");
    let mut book = WasmGroupBook::from_parts(outsider.device_id(), GroupBook::new());
    let err = book
        .ingest_manifest_inner(&roster, &m.root.device_id(), &m.manifest, NOW)
        .unwrap_err();
    assert!(
        err.contains("local device is not an active member"),
        "{err}"
    );
}

#[test]
fn first_contact_refuses_crl_revoked_signer() {
    let m = mesh();
    let mut roster = roster_with_root(&m);
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: "root-host".to_owned(),
            seq: 1,
            revoked_devices: vec![m.root.device_id()],
            revoked_nonces: Vec::new(),
            ts: CRL_TS.to_owned(),
        },
        m.root.id.signing_key(),
    )
    .unwrap();
    roster
        .ingest_crl(crl, "root-host", m.root.id.signing_key().public_key())
        .unwrap();
    let mut book = local_book(&m);
    assert!(
        book.ingest_manifest_inner(&roster, &m.root.device_id(), &m.manifest, NOW)
            .is_err()
    );
}

#[test]
fn known_group_updates_and_revocation_removes_authority() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    let sib = m.sibling.device_id();
    let send = format!("group.send:{}", m.group_id);
    book.authorize_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap();

    let revoked = revoke_sibling(&m);
    let out = book
        .ingest_manifest_inner(&roster, &m.local.device_id(), &revoked, NOW + 10)
        .unwrap();
    assert_eq!(out.status, GroupIngestStatus::Updated);
    assert_eq!(out.newly_revoked, vec![sib.clone()]);

    let err = book
        .authorize_inner(&roster, &m.group_id, &sib, &send, NOW + 10)
        .unwrap_err();
    assert!(err.contains(&sib), "{err}");
    let targets = book
        .broadcast_targets_inner(&roster, &m.group_id, None, NOW + 10)
        .unwrap();
    assert!(targets.is_empty(), "{targets:?}");

    let stale = book
        .ingest_manifest_inner(&roster, &m.root.device_id(), &m.manifest, NOW + 20)
        .unwrap_err();
    assert!(stale.to_lowercase().contains("rollback"), "{stale}");
}

#[test]
fn broadcast_targets_filter_by_recv_cap_and_require_local_send() {
    let m = mesh();
    let (book, roster) = pinned(&m);
    let targets = book
        .broadcast_targets_inner(&roster, &m.group_id, None, NOW)
        .unwrap();
    assert_eq!(targets, vec![m.sibling.device_id()]);
    assert!(!targets.contains(&m.local.device_id()));

    let err = book
        .broadcast_targets_inner(
            &roster,
            &m.group_id,
            Some(&format!("group.admin:{}", m.group_id)),
            NOW,
        )
        .unwrap_err();
    assert!(err.contains("not a group admin"), "{err}");
}

#[test]
fn authorize_rejects_foreign_group_scope_unknown_peers_and_expiry() {
    let m = mesh();
    let (book, roster) = pinned(&m);
    let sib = m.sibling.device_id();
    assert!(
        book.authorize_inner(&roster, &m.group_id, &sib, "group.send:grp_other", NOW)
            .is_err()
    );
    assert!(
        book.authorize_inner(
            &roster,
            &m.group_id,
            "dev_unknown",
            &format!("group.send:{}", m.group_id),
            NOW
        )
        .is_err()
    );
    assert!(
        book.authorize_inner(&roster, "grp_missing", &sib, "group.send:grp_missing", NOW)
            .is_err()
    );
    let far = NOW + 200 * 86_400;
    assert!(
        book.authorize_inner(
            &roster,
            &m.group_id,
            &sib,
            &format!("group.send:{}", m.group_id),
            far
        )
        .is_err()
    );
    assert!(
        book.broadcast_targets_inner(&roster, &m.group_id, None, far)
            .is_err()
    );
}

#[test]
fn authorize_applies_root_crl_stored_under_root_device_id() {
    let m = mesh();
    let (book, mut roster) = pinned(&m);
    let sib = m.sibling.device_id();
    let send = format!("group.send:{}", m.group_id);
    book.authorize_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap();
    ingest_root_crl(&m, &mut roster, vec![sib.clone()]);
    let err = book
        .authorize_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap_err();
    assert!(err.contains(&sib), "{err}");
    let targets = book
        .broadcast_targets_inner(&roster, &m.group_id, None, NOW)
        .unwrap();
    assert!(!targets.contains(&sib));
}

#[test]
fn authorize_applies_root_crl_stored_under_root_host_id() {
    let m = mesh();
    let (book, mut roster) = pinned(&m);
    let host = m.root.id.host_id().to_owned();
    assert_ne!(host, m.root.device_id());
    let sib = m.sibling.device_id();
    let send = format!("group.send:{}", m.group_id);
    let list = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host.clone(),
            seq: 1,
            revoked_devices: vec![sib.clone()],
            revoked_nonces: Vec::new(),
            ts: CRL_TS.to_owned(),
        },
        m.root.id.signing_key(),
    )
    .unwrap();
    roster
        .ingest_crl(list, &host, m.root.id.signing_key().public_key())
        .unwrap();
    let err = book
        .authorize_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap_err();
    assert!(err.contains(&sib), "{err}");
    let targets = book
        .broadcast_targets_inner(&roster, &m.group_id, None, NOW)
        .unwrap();
    assert!(targets.is_empty(), "{targets:?}");
}

#[test]
fn co_admin_manifest_is_accepted_with_root_crl_when_root_host_id_differs() {
    let m = mesh();
    let (mut book, mut roster) = pinned(&m);
    assert_ne!(m.root.id.host_id(), m.root.device_id());
    let params = GroupBuildParams::new(NOW + 10);
    let sib = m.sibling.device_id();
    let grant = issue_admin_grant(
        m.root.id.signing_key(),
        &m.root.device_id(),
        &m.group_id,
        &sib,
        m.sibling.id.signing_key().public_key(),
        0,
        params,
    )
    .unwrap();
    let co_admin = GroupSigner::co_admin(m.sibling.id.signing_key(), sib.clone(), grant);
    let extra = Actor::new("extra-host");
    let (grown, _) = add_member(
        &m.manifest,
        &co_admin,
        extra.member(caps(&m.group_id)),
        &m.secrets,
        params,
    )
    .unwrap();

    ingest_root_crl(&m, &mut roster, vec![Actor::new("other-host").device_id()]);
    let out = book
        .ingest_manifest_inner(&roster, &sib, &grown, NOW + 10)
        .unwrap();
    assert_eq!(out.status, GroupIngestStatus::Updated);
    assert_eq!(book.inner.manifest(&m.group_id).unwrap().seq, grown.seq);
}

#[test]
fn root_crl_revoking_the_co_admin_blocks_its_manifest() {
    let m = mesh();
    let (mut book, mut roster) = pinned(&m);
    let params = GroupBuildParams::new(NOW + 10);
    let sib = m.sibling.device_id();
    let grant = issue_admin_grant(
        m.root.id.signing_key(),
        &m.root.device_id(),
        &m.group_id,
        &sib,
        m.sibling.id.signing_key().public_key(),
        0,
        params,
    )
    .unwrap();
    let co_admin = GroupSigner::co_admin(m.sibling.id.signing_key(), sib.clone(), grant);
    let extra = Actor::new("extra-host");
    let (grown, _) = add_member(
        &m.manifest,
        &co_admin,
        extra.member(caps(&m.group_id)),
        &m.secrets,
        params,
    )
    .unwrap();
    ingest_root_crl(&m, &mut roster, vec![sib.clone()]);
    assert!(
        book.ingest_manifest_inner(&roster, &sib, &grown, NOW + 10)
            .is_err()
    );
    assert_eq!(book.inner.manifest(&m.group_id).unwrap().seq, 3);
}

#[test]
fn members_lists_active_members_and_revoked_ids() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    let view = book.members_inner(&m.group_id).unwrap();
    assert_eq!(view["members"].as_array().unwrap().len(), 3);
    assert_eq!(view["seq"], 3);

    let revoked = revoke_sibling(&m);
    book.ingest_manifest_inner(&roster, &m.root.device_id(), &revoked, NOW + 10)
        .unwrap();
    let view = book.members_inner(&m.group_id).unwrap();
    let ids: Vec<&str> = view["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["device_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(!ids.contains(&m.sibling.device_id().as_str()));
    assert_eq!(view["revoked"][0], m.sibling.device_id());
    assert!(book.members_inner("grp_missing").is_err());
}

#[test]
fn unverified_event_ingests_only_through_core_verification() {
    let m = mesh();
    let roster = roster_with_root(&m);
    let event = json!({
        "event": "group_manifest_unverified",
        "group_id": m.manifest.group_id,
        "seq": m.manifest.seq,
        "manifest_json": String::from_utf8(m.manifest.to_wire_bytes().unwrap()).unwrap(),
    })
    .to_string();
    let mut book = local_book(&m);
    let out = book
        .ingest_event_inner(&roster, &m.root.device_id(), &event, NOW)
        .unwrap();
    assert_eq!(out.status, GroupIngestStatus::Created);

    let wrong = json!({"event": "data"}).to_string();
    assert!(
        book.ingest_event_inner(&roster, &m.root.device_id(), &wrong, NOW)
            .is_err()
    );

    let mut forged = m.manifest.clone();
    forged.members[1].caps.push("group.admin".to_owned());
    let tampered = json!({
        "event": "group_manifest_unverified",
        "manifest_json": String::from_utf8(forged.to_wire_bytes().unwrap()).unwrap(),
    })
    .to_string();
    let mut fresh = local_book(&m);
    assert!(
        fresh
            .ingest_event_inner(&roster, &m.root.device_id(), &tampered, NOW)
            .is_err()
    );
    assert!(fresh.inner.group_ids().is_empty());
}

#[test]
fn gossip_style_second_hand_manifest_cannot_pin_a_new_group() {
    let m = mesh();
    let mut roster = roster_with_root(&m);
    pin(&mut roster, &m.sibling);
    let mut book = local_book(&m);
    assert!(
        book.ingest_manifest_inner(&roster, &m.sibling.device_id(), &m.manifest, NOW)
            .is_err()
    );
    assert!(book.inner.group_ids().is_empty());
}

fn frame(group_id: &str, seq: u64, key: u8) -> GroupRendezvousFrame {
    let bytes = encode_group_rendezvous_frame(group_id, seq, &[key; 32]).unwrap();
    decode_group_rendezvous_frame(bytes.as_ref()).unwrap()
}

#[test]
fn rendezvous_applies_only_from_admins_at_the_stored_seq() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    let seq = m.manifest.seq;

    let from_member = book.apply_rendezvous_inner(
        &roster,
        Some(&m.sibling.device_id()),
        &[frame(&m.group_id, seq, 7)],
        NOW,
    );
    assert_eq!(from_member["applied"].as_array().unwrap().len(), 0);
    assert_eq!(from_member["rejected"].as_array().unwrap().len(), 1);
    assert!(book.inner.secrets(&m.group_id).is_none());

    let ahead = book.apply_rendezvous_inner(
        &roster,
        Some(&m.root.device_id()),
        &[frame(&m.group_id, seq + 1, 7)],
        NOW,
    );
    assert_eq!(ahead["rejected"].as_array().unwrap().len(), 1);

    let unauth = book.apply_rendezvous_inner(&roster, None, &[frame(&m.group_id, seq, 7)], NOW);
    assert_eq!(unauth["rejected"].as_array().unwrap().len(), 1);

    let ok = book.apply_rendezvous_inner(
        &roster,
        Some(&m.root.device_id()),
        &[frame(&m.group_id, seq, 7)],
        NOW,
    );
    assert_eq!(ok["applied"].as_array().unwrap().len(), 1);
    let secrets = book.inner.secrets(&m.group_id).unwrap();
    assert_eq!(secrets.seq(), seq);
    let rendered = ok.to_string();
    assert!(!rendered.contains(&b64url_encode(&[7u8; 32])), "{rendered}");
}

#[test]
fn rendezvous_for_unknown_group_is_rejected() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    let out = book.apply_rendezvous_inner(
        &roster,
        Some(&m.root.device_id()),
        &[frame(&mesh().group_id, 1, 9)],
        NOW,
    );
    assert_eq!(out["rejected"].as_array().unwrap().len(), 1);
}

#[test]
fn state_roundtrips_through_json_with_secrets_intact() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    book.apply_rendezvous_inner(
        &roster,
        Some(&m.root.device_id()),
        &[frame(&m.group_id, m.manifest.seq, 3)],
        NOW,
    );
    let saved = serde_json::to_string(&book.inner).unwrap();
    let restored: GroupBook = serde_json::from_str(&saved).unwrap();
    assert_eq!(restored, book.inner);
    assert!(restored.secrets(&m.group_id).is_some());
}

#[test]
fn local_group_capacity_is_enforced() {
    let local = Actor::new("web-host");
    let mut book = WasmGroupBook::from_parts(local.device_id(), GroupBook::new());
    let mut roster = Roster::new();
    let params = GroupBuildParams::new(NOW);
    let mut last = None;
    for i in 0..=MAX_LOCAL_GROUPS {
        let root = Actor::new(&format!("root-{i}"));
        pin(&mut roster, &root);
        let (m1, s1) = create_group(
            root.id.signing_key(),
            "g",
            1,
            root.member(Vec::new()),
            params,
        )
        .unwrap();
        let gid = m1.group_id.clone();
        let (m2, _) = add_member(
            &m1,
            &GroupSigner::root(root.id.signing_key()),
            local.member(caps(&gid)),
            &s1,
            params,
        )
        .unwrap();
        let res = book.ingest_manifest_inner(&roster, &root.device_id(), &m2, NOW);
        if i < MAX_LOCAL_GROUPS {
            res.unwrap();
        } else {
            last = Some(res);
        }
    }
    let err = last.unwrap().unwrap_err();
    assert!(err.contains("local groups"), "{err}");
    assert_eq!(book.inner.group_ids().len(), MAX_LOCAL_GROUPS);
}

fn remove_local(m: &Mesh) -> GroupManifest {
    let signer = GroupSigner::root(m.root.id.signing_key());
    remove_member(
        &m.manifest,
        &signer,
        &m.local.device_id(),
        &m.secrets,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap()
    .0
}

/// A group rooted at a throwaway actor in which `admin` is a co-admin that signed the manifest
/// adding `local`.
fn co_admin_group(admin: &Actor, local: &Actor) -> GroupManifest {
    let root = Actor::new("throwaway-root");
    let params = GroupBuildParams::new(NOW);
    let (m1, s1) = create_group(
        root.id.signing_key(),
        "co",
        1,
        root.member(Vec::new()),
        params,
    )
    .unwrap();
    let gid = m1.group_id.clone();
    let (m2, s2) = add_member(
        &m1,
        &GroupSigner::root(root.id.signing_key()),
        admin.member(caps(&gid)),
        &s1,
        params,
    )
    .unwrap();
    let grant = issue_admin_grant(
        root.id.signing_key(),
        &root.device_id(),
        &gid,
        &admin.device_id(),
        admin.id.signing_key().public_key(),
        0,
        params,
    )
    .unwrap();
    let co = GroupSigner::co_admin(admin.id.signing_key(), admin.device_id(), grant);
    add_member(&m2, &co, local.member(caps(&gid)), &s2, params)
        .unwrap()
        .0
}

#[test]
fn first_contact_quota_applies_per_peer() {
    let local = Actor::new("web-host");
    let s = Actor::new("s-host");
    let t = Actor::new("t-host");
    let mut book = WasmGroupBook::from_parts(local.device_id(), GroupBook::new());
    let mut roster = Roster::new();
    pin(&mut roster, &s);
    pin(&mut roster, &t);
    for _ in 0..MAX_GROUPS_PER_SIGNER {
        let m = co_admin_group(&s, &local);
        book.ingest_manifest_inner(&roster, &s.device_id(), &m, NOW)
            .unwrap();
    }
    let m = co_admin_group(&s, &local);
    let err = book
        .ingest_manifest_inner(&roster, &s.device_id(), &m, NOW)
        .unwrap_err();
    assert!(err.contains("pinned by this peer"), "{err}");
    assert!(book.inner.manifest(&m.group_id).is_none());
    let m = co_admin_group(&t, &local);
    book.ingest_manifest_inner(&roster, &t.device_id(), &m, NOW)
        .unwrap();
    assert_eq!(book.inner.group_ids().len(), MAX_GROUPS_PER_SIGNER + 1);
}

#[test]
fn removed_local_device_drops_secrets_and_refuses_rendezvous() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    let seq = m.manifest.seq;
    let applied = book.apply_rendezvous_inner(
        &roster,
        Some(&m.root.device_id()),
        &[frame(&m.group_id, seq, 7)],
        NOW,
    );
    assert_eq!(applied["applied"].as_array().unwrap().len(), 1);
    assert!(book.inner.secrets(&m.group_id).is_some());

    let removed = remove_local(&m);
    book.ingest_manifest_inner(&roster, &m.root.device_id(), &removed, NOW + 10)
        .unwrap();
    assert!(book.inner.secrets(&m.group_id).is_none());
    assert!(book.inner.manifest(&m.group_id).is_some());

    let out = book.apply_rendezvous_inner(
        &roster,
        Some(&m.root.device_id()),
        &[frame(&m.group_id, removed.seq, 8)],
        NOW + 10,
    );
    assert_eq!(out["applied"].as_array().unwrap().len(), 0);
    let error = out["rejected"][0]["error"].as_str().unwrap();
    assert!(error.contains("not an active member"), "{error}");
    assert!(book.inner.secrets(&m.group_id).is_none());
}

#[test]
fn stored_group_cap_counts_groups_the_local_device_left() {
    let local = Actor::new("web-host");
    let mut book = WasmGroupBook::from_parts(local.device_id(), GroupBook::new());
    let mut roster = Roster::new();
    let params = GroupBuildParams::new(NOW);
    let mut refused = None;
    for i in 0..=MAX_STORED_GROUPS {
        let root = Actor::new(&format!("root-{i}"));
        pin(&mut roster, &root);
        let signer = GroupSigner::root(root.id.signing_key());
        let (m1, s1) = create_group(
            root.id.signing_key(),
            "g",
            1,
            root.member(Vec::new()),
            params,
        )
        .unwrap();
        let gid = m1.group_id.clone();
        let (m2, s2) = add_member(&m1, &signer, local.member(caps(&gid)), &s1, params).unwrap();
        let res = book.ingest_manifest_inner(&roster, &root.device_id(), &m2, NOW);
        if i == MAX_STORED_GROUPS {
            refused = Some(res);
            continue;
        }
        res.unwrap();
        let (m3, _) = remove_member(
            &m2,
            &signer,
            &local.device_id(),
            &s2,
            GroupBuildParams::new(NOW + 10),
        )
        .unwrap();
        book.ingest_manifest_inner(&roster, &root.device_id(), &m3, NOW + 10)
            .unwrap();
    }
    let err = refused.unwrap().unwrap_err();
    assert!(err.contains("stored groups"), "{err}");
    assert_eq!(book.inner.group_ids().len(), MAX_STORED_GROUPS);
}

#[test]
fn check_local_member_requires_active_membership() {
    let m = mesh();
    let (book, roster) = pinned(&m);
    book.check_local_member_inner(&roster, &m.group_id).unwrap();
    assert!(
        book.check_local_member_inner(&roster, "grp_missing")
            .is_err()
    );
    let outsider = WasmGroupBook::from_parts(m.sibling.device_id(), book.inner.clone());
    outsider
        .check_local_member_inner(&roster, &m.group_id)
        .unwrap();
    let stranger = WasmGroupBook::from_parts(Actor::new("x").device_id(), book.inner.clone());
    assert!(
        stranger
            .check_local_member_inner(&roster, &m.group_id)
            .is_err()
    );
}

fn root_crl_revoking(m: &Mesh, revoked: Vec<String>) -> tendril_core::grants::RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: m.root.device_id(),
            seq: 1,
            revoked_devices: revoked,
            revoked_nonces: Vec::new(),
            ts: CRL_TS.to_owned(),
        },
        m.root.id.signing_key(),
    )
    .unwrap()
}

fn ingest_root_crl(m: &Mesh, roster: &mut Roster, revoked: Vec<String>) {
    let root_id = m.root.device_id();
    roster
        .ingest_crl(
            root_crl_revoking(m, revoked),
            &root_id,
            m.root.id.signing_key().public_key(),
        )
        .unwrap();
}

#[test]
fn local_revoked_by_manifest_refuses_inbound_and_broadcast() {
    let m = mesh();
    let (mut book, roster) = pinned(&m);
    let sib = m.sibling.device_id();
    let send = format!("group.send:{}", m.group_id);
    book.authorize_inbound_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap();

    let signer = GroupSigner::root(m.root.id.signing_key());
    let (revoked, _) = remove_member(
        &m.manifest,
        &signer,
        &m.local.device_id(),
        &m.secrets,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap();
    book.ingest_manifest_inner(&roster, &m.root.device_id(), &revoked, NOW + 10)
        .unwrap();

    let err = book
        .authorize_inbound_inner(&roster, &m.group_id, &sib, &send, NOW + 10)
        .unwrap_err();
    assert!(err.contains("not an active member"), "{err}");
    assert!(book.check_local_member_inner(&roster, &m.group_id).is_err());
    assert!(
        book.broadcast_targets_inner(&roster, &m.group_id, None, NOW + 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn local_revoked_by_root_crl_refuses_inbound_and_broadcast() {
    let m = mesh();
    let (book, mut roster) = pinned(&m);
    let sib = m.sibling.device_id();
    let send = format!("group.send:{}", m.group_id);
    book.authorize_inbound_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap();
    assert_eq!(
        book.broadcast_targets_inner(&roster, &m.group_id, None, NOW)
            .unwrap(),
        vec![sib.clone()]
    );

    ingest_root_crl(&m, &mut roster, vec![m.local.device_id()]);

    let err = book
        .authorize_inbound_inner(&roster, &m.group_id, &sib, &send, NOW)
        .unwrap_err();
    assert!(err.contains(&m.local.device_id()), "{err}");
    assert!(book.check_local_member_inner(&roster, &m.group_id).is_err());
    assert!(
        book.broadcast_targets_inner(&roster, &m.group_id, None, NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn inbound_from_unauthorized_sender_is_refused_while_local_is_active() {
    let m = mesh();
    let (book, roster) = pinned(&m);
    let send = format!("group.send:{}", m.group_id);
    let stranger = Actor::new("stranger-host").device_id();
    assert!(
        book.authorize_inbound_inner(&roster, &m.group_id, &stranger, &send, NOW)
            .is_err()
    );
}

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../bindings/web/test/fixtures/group.json"
);
const FIXTURE_ENV: &str = "TENDRIL_REGEN_WEB_GROUP_FIXTURE";

/// Builds the signed material the Web SDK tests replay: one group with a root, the browser
/// identity, and three siblings, plus a revocation of sibling `a` and an unrelated group.
fn build_web_fixture() -> Value {
    let root = Actor::new("root-host");
    let local = WasmIdentity::generate_inner(Some("web-local")).unwrap();
    let local_actor = Actor {
        id: EndpointIdentity::from_persisted(
            local.inner.host_id().to_owned(),
            tendril_core::crypto::StaticKeypair::from_scalar(
                *local.inner.static_key().secret_bytes(),
            ),
            tendril_core::crypto::SigningKeypair::from_seeds(
                *local.inner.signing_key().seed_bytes(),
                *local.inner.signing_key().mldsa_seed_bytes(),
            ),
            Vec::new(),
            0,
        )
        .unwrap(),
    };
    let a = Actor::new("sib-a");
    let b = Actor::new("sib-b");
    let c = Actor::new("sib-c");
    let params = GroupBuildParams::new(NOW).with_validity_secs(90 * 86_400);
    let signer = GroupSigner::root(root.id.signing_key());

    let (mut manifest, mut secrets) = create_group(
        root.id.signing_key(),
        "web-mesh",
        1,
        root.member(Vec::new()),
        params,
    )
    .unwrap();
    let gid = manifest.group_id.clone();
    let both = caps(&gid);
    let members = [
        (&local_actor, both.clone()),
        (&a, both.clone()),
        (&b, vec![both[0].clone()]),
        (&c, vec![both[1].clone()]),
    ];
    for (actor, member_caps) in members {
        let next = add_member(
            &manifest,
            &signer,
            actor.member(member_caps),
            &secrets,
            params,
        )
        .unwrap();
        (manifest, secrets) = next;
    }
    let (revoked, _) = remove_member(&manifest, &signer, &a.device_id(), &secrets, params).unwrap();
    let (revoked_local, _) = remove_member(
        &manifest,
        &signer,
        &local_actor.device_id(),
        &secrets,
        params,
    )
    .unwrap();

    let stranger_root = Actor::new("stranger-root");
    let (s1, s1_secrets) = create_group(
        stranger_root.id.signing_key(),
        "other",
        1,
        stranger_root.member(Vec::new()),
        params,
    )
    .unwrap();
    let stranger_gid = s1.group_id.clone();
    let (stranger, _) = add_member(
        &s1,
        &GroupSigner::root(stranger_root.id.signing_key()),
        local_actor.member(caps(&stranger_gid)),
        &s1_secrets,
        params,
    )
    .unwrap();

    let mut roster = Roster::new();
    pin(&mut roster, &root);
    let mut crl_roster = roster.clone();
    let root_id = root.device_id();
    crl_roster
        .ingest_crl(
            sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: root_id.clone(),
                    seq: 1,
                    revoked_devices: vec![local_actor.device_id()],
                    revoked_nonces: Vec::new(),
                    ts: CRL_TS.to_owned(),
                },
                root.id.signing_key(),
            )
            .unwrap(),
            &root_id,
            root.id.signing_key().public_key(),
        )
        .unwrap();
    json!({
        "now": NOW,
        "group_id": gid,
        "local": {
            "identity_json": &*local.serialize_json().unwrap(),
            "device_id": local_actor.device_id(),
        },
        "roster_json": serde_json::to_string(&roster).unwrap(),
        "roster_local_crl_json": serde_json::to_string(&crl_roster).unwrap(),
        "root_device_id": root.device_id(),
        "peers": {
            "a": a.device_id(),
            "b": b.device_id(),
            "c": c.device_id(),
        },
        "manifest": manifest,
        "manifest_revoke_a": revoked,
        "manifest_revoke_local": revoked_local,
        "stranger_manifest": stranger,
        "stranger_root_device_id": stranger_root.device_id(),
    })
}

#[test]
#[ignore = "rewrites bindings/web/test/fixtures/group.json when TENDRIL_REGEN_WEB_GROUP_FIXTURE is set"]
fn regenerate_web_group_fixture() {
    if std::env::var_os(FIXTURE_ENV).is_none() {
        return;
    }
    let body = serde_json::to_string_pretty(&build_web_fixture()).unwrap();
    std::fs::create_dir_all(std::path::Path::new(FIXTURE_PATH).parent().unwrap()).unwrap();
    std::fs::write(FIXTURE_PATH, format!("{body}\n")).unwrap();
}

/// Fails when the checked-in Web SDK fixture no longer matches the core manifest format.
/// Regenerate with `TENDRIL_REGEN_WEB_GROUP_FIXTURE=1 cargo test -p tendril-wasm
/// regenerate_web_group_fixture -- --ignored`.
#[test]
fn web_group_fixture_replays_through_the_group_book() {
    let raw = std::fs::read_to_string(FIXTURE_PATH).expect("web group fixture is checked in");
    let fx: Value = serde_json::from_str(&raw).unwrap();
    let now = fx["now"].as_u64().unwrap();
    let local = WasmIdentity::parse_json(fx["local"]["identity_json"].as_str().unwrap()).unwrap();
    assert_eq!(
        local.inner.device_id(),
        fx["local"]["device_id"].as_str().unwrap()
    );
    let roster: Roster = serde_json::from_str(fx["roster_json"].as_str().unwrap()).unwrap();
    let root_id = fx["root_device_id"].as_str().unwrap();
    let manifest: GroupManifest = serde_json::from_value(fx["manifest"].clone()).unwrap();
    let revoked: GroupManifest = serde_json::from_value(fx["manifest_revoke_a"].clone()).unwrap();
    let stranger: GroupManifest = serde_json::from_value(fx["stranger_manifest"].clone()).unwrap();
    let revoked_local: GroupManifest =
        serde_json::from_value(fx["manifest_revoke_local"].clone()).unwrap();
    let crl_roster: Roster =
        serde_json::from_str(fx["roster_local_crl_json"].as_str().unwrap()).unwrap();

    let mut book = WasmGroupBook::from_parts(local.inner.device_id(), GroupBook::new());
    let out = book
        .ingest_manifest_inner(&roster, root_id, &manifest, now)
        .unwrap();
    assert_eq!(out.status, GroupIngestStatus::Created);
    let out = book
        .ingest_manifest_inner(&roster, root_id, &revoked, now)
        .unwrap();
    assert_eq!(out.newly_revoked, vec![fx["peers"]["a"].as_str().unwrap()]);
    assert!(
        book.check_local_member_inner(&roster, &manifest.group_id)
            .is_ok()
    );
    assert!(
        book.check_local_member_inner(&crl_roster, &manifest.group_id)
            .is_err()
    );
    let mut gone = WasmGroupBook::from_parts(local.inner.device_id(), GroupBook::new());
    gone.ingest_manifest_inner(&roster, root_id, &manifest, now)
        .unwrap();
    let out = gone
        .ingest_manifest_inner(&roster, root_id, &revoked_local, now)
        .unwrap();
    assert_eq!(out.newly_revoked, vec![local.inner.device_id()]);
    assert!(
        gone.check_local_member_inner(&roster, &manifest.group_id)
            .is_err()
    );
    assert!(
        book.ingest_manifest_inner(
            &roster,
            fx["stranger_root_device_id"].as_str().unwrap(),
            &stranger,
            now
        )
        .is_err()
    );
}
