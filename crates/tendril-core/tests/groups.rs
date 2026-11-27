//! Group mesh core tests: manifest verification, ingestion rulings R1 to R8, rendezvous keys, frames.

use std::collections::BTreeSet;

use tendril_core::crypto::{
    HybridSigningPublicKey, SigningKeypair, StaticKeypair, b64url_encode, device_id,
    x25519_public_from_scalar,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{
    Capability, RevocationList, RevocationListUnsigned, canonical_json, sign_crl, sign_grant,
};
use tendril_core::group::{
    DEFAULT_MANIFEST_VALIDITY_SECS, GROUP_RENDEZVOUS_FRAME_LEN, GroupBook, GroupBuildParams,
    GroupIngestStatus, GroupManifest, GroupManifestUnsigned, GroupMember, GroupSeq, GroupSigner,
    MAX_GOSSIP_GROUPS, MAX_GROUP_CO_ADMINS, MAX_GROUP_MANIFEST_LEN, MAX_GROUP_MEMBERS,
    MAX_GROUPS_PER_SIGNER, MAX_LOCAL_GROUPS, MAX_MANIFEST_VALIDITY_SECS, MAX_REVOKED_MEMBERS,
    MAX_STORED_GROUPS, V2GroupSecrets, add_member, check_first_contact, check_group_capacity,
    check_rendezvous_local_membership, decode_group_rendezvous_frame, derive_group_mailbox_secret,
    derive_pair_bootstrap, drop_secrets_if_left, encode_group_rendezvous_frame, group_id_from_root,
    group_manifest_signed_bytes, issue_admin_grant, remove_member, renew_manifest, root_crl,
    root_device_in, set_min_wire_version, sign_group_manifest, verify_group_manifest,
};
use tendril_core::identity::EndpointIdentity;
use tendril_core::roster::{Roster, V2PeerSecrets};
use tendril_core::session::{SessionAction, SessionMachine};
use tendril_core::v2::{
    PaddingPolicy, V2InnerFrame, V2SessionAction, V2SessionInitiator, V2SessionResponder,
    decode_v2_inner_frame, pad_inner_frame,
};
use tendril_core::wire::{InnerFrameType, SessionHello, decode_inner_frame, encode_inner_frame};

const NOW: u64 = 1_795_564_800;

struct Dev {
    st: StaticKeypair,
    sk: SigningKeypair,
}

impl Dev {
    fn new(seed: u8) -> Self {
        let mut scalar = [seed; 32];
        scalar[0] = seed ^ 0x5A;
        Self {
            st: StaticKeypair::from_scalar(scalar),
            sk: SigningKeypair::from_seed([seed.wrapping_add(0x80); 32]),
        }
    }

    fn id(&self) -> String {
        device_id(self.st.public_bytes())
    }

    fn member(&self, name: &str, caps: Vec<String>) -> GroupMember {
        GroupMember::new(
            self.st.public_bytes(),
            name,
            self.sk.public_key(),
            vec!["wss://relay.example/v2/relay".to_string()],
            caps,
        )
    }
}

fn std_caps(gid: &str) -> Vec<String> {
    vec![format!("group.send:{gid}"), format!("group.recv:{gid}")]
}

fn params() -> GroupBuildParams {
    GroupBuildParams::new(NOW)
}

struct Fixture {
    root: Dev,
    gid: String,
    manifest: GroupManifest,
    secrets: V2GroupSecrets,
}

fn fixture() -> Fixture {
    let root = Dev::new(1);
    let gid = group_id_from_root(root.sk.public_key());
    let (manifest, secrets) = tendril_core::group::create_group(
        &root.sk,
        "home",
        2,
        root.member("root", std_caps(&gid)),
        params(),
    )
    .unwrap();
    Fixture {
        root,
        gid,
        manifest,
        secrets,
    }
}

fn unsigned_of(m: &GroupManifest) -> GroupManifestUnsigned {
    m.unsigned()
}

fn resign_root(fx: &Fixture, unsigned: GroupManifestUnsigned) -> GroupManifest {
    sign_group_manifest(unsigned, &fx.root.sk).unwrap()
}

fn ingest(book: &mut GroupBook, m: &GroupManifest) -> Result<(), CoreError> {
    book.ingest_group_manifest(m, NOW, None).map(|_| ())
}

fn invalid_msg(err: &CoreError) -> &str {
    match err {
        CoreError::InvalidGroupManifest(m) => m,
        other => panic!("expected InvalidGroupManifest, got {other:?}"),
    }
}

fn co_admin_fixture() -> (
    Fixture,
    Dev,
    tendril_core::grants::Grant,
    GroupManifest,
    V2GroupSecrets,
) {
    let fx = fixture();
    let admin = Dev::new(2);
    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        admin.member("admin", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let grant = issue_admin_grant(
        &fx.root.sk,
        &fx.root.id(),
        &fx.gid,
        &admin.id(),
        admin.sk.public_key(),
        0,
        params(),
    )
    .unwrap();
    (fx, admin, grant, m2, s2)
}

#[test]
fn group_id_is_derived_from_root_key() {
    let fx = fixture();
    assert_eq!(fx.gid.len(), 20);
    assert!(fx.gid.starts_with("grp_"));
    assert_eq!(fx.manifest.group_id, fx.gid);
    let mut bad = unsigned_of(&fx.manifest);
    bad.group_id = "grp_0000000000000000".to_string();
    let err = verify_group_manifest(&resign_root(&fx, bad), NOW, None).unwrap_err();
    assert!(invalid_msg(&err).contains("group_id"));
}

#[test]
fn created_manifest_verifies_and_roundtrips() {
    let fx = fixture();
    let verified = verify_group_manifest(&fx.manifest, NOW, None).unwrap();
    assert_eq!(verified.root_device_id(), fx.root.id());
    assert!(!verified.signed_by_co_admin());
    assert_eq!(fx.manifest.seq, 1);
    assert_eq!(fx.secrets.seq(), 1);
    let wire = fx.manifest.to_wire_bytes().unwrap();
    assert_eq!(GroupManifest::from_wire_bytes(&wire).unwrap(), fx.manifest);
    let mut tampered = fx.manifest.clone();
    tampered.name = "other".to_string();
    assert_eq!(
        verify_group_manifest(&tampered, NOW, None).unwrap_err(),
        CoreError::InvalidSignature
    );
}

#[test]
fn unknown_fields_and_null_optionals_are_rejected_or_canonical() {
    let fx = fixture();
    let mut v = serde_json::to_value(&fx.manifest).unwrap();
    v["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<GroupManifest>(v).is_err());
    let mut member = serde_json::to_value(&fx.manifest.members[0]).unwrap();
    member["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<GroupMember>(member).is_err());
}

#[test]
fn r1_seq_rules_and_root_pinning() {
    let fx = fixture();
    let mut book = GroupBook::new();
    let out = book.ingest_group_manifest(&fx.manifest, NOW, None).unwrap();
    assert_eq!(out.status, GroupIngestStatus::Created);
    assert_eq!(out.newly_joined, vec![fx.root.id()]);
    assert_eq!(
        book.root_signing_pub(&fx.gid),
        Some(fx.root.sk.public_key())
    );

    let again = book.ingest_group_manifest(&fx.manifest, NOW, None).unwrap();
    assert_eq!(again.status, GroupIngestStatus::Unchanged);
    assert!(again.newly_joined.is_empty());

    let peer = Dev::new(3);
    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let up = book.ingest_group_manifest(&m2, NOW, None).unwrap();
    assert_eq!(up.status, GroupIngestStatus::Updated);
    assert_eq!(up.seq, 2);
    assert_eq!(up.newly_joined, vec![peer.id()]);
    assert!(up.newly_revoked.is_empty());
    assert_eq!(s2.seq(), 2);

    assert_eq!(
        ingest(&mut book, &fx.manifest).unwrap_err(),
        CoreError::GroupSeqRollback { current: 2, got: 1 }
    );

    let mut fork = unsigned_of(&m2);
    fork.name = "forked".to_string();
    let forked = resign_root(&fx, fork);
    assert_eq!(
        ingest(&mut book, &forked).unwrap_err(),
        CoreError::GroupManifestFork { seq: 2 }
    );

    let mut resigned = unsigned_of(&m2);
    resigned.ts = m2.ts.clone();
    let same_content = resign_root(&fx, resigned);
    let out = book
        .ingest_group_manifest(&same_content, NOW, None)
        .unwrap();
    assert_eq!(out.status, GroupIngestStatus::Unchanged);

    let other_root = Dev::new(9);
    let other_gid = group_id_from_root(other_root.sk.public_key());
    let (foreign, _) = tendril_core::group::create_group(
        &other_root.sk,
        "foreign",
        2,
        other_root.member("r", std_caps(&other_gid)),
        params(),
    )
    .unwrap();
    let mut spoof = unsigned_of(&foreign);
    spoof.group_id = fx.gid.clone();
    let spoofed = sign_group_manifest(spoof, &other_root.sk).unwrap();
    assert!(ingest(&mut book, &spoofed).is_err());
}

#[test]
fn gossiped_manifest_cannot_create_a_group() {
    let fx = fixture();
    let mut book = GroupBook::new();
    assert_eq!(
        book.ingest_gossiped_manifest(&fx.manifest, NOW, None)
            .unwrap_err(),
        CoreError::GroupNotFound(fx.gid.clone())
    );
    ingest(&mut book, &fx.manifest).unwrap();
    assert_eq!(
        book.ingest_gossiped_manifest(&fx.manifest, NOW, None)
            .unwrap()
            .status,
        GroupIngestStatus::Unchanged
    );
}

fn many_members(fx: &Fixture, count: usize, endpoints: usize, ep_len: usize) -> Vec<GroupMember> {
    let mut members = vec![fx.root.member("root", std_caps(&fx.gid))];
    for i in 0..count - 1 {
        let dev = Dev::new(10 + u8::try_from(i).unwrap());
        let mut m = dev.member(&format!("member-{i}"), std_caps(&fx.gid));
        m.endpoints = (0..endpoints)
            .map(|e| {
                let base = format!("wss://relay{e}.example/");
                format!("{base}{}", "a".repeat(ep_len.saturating_sub(base.len())))
            })
            .collect();
        members.push(m);
    }
    members
}

#[test]
fn r2_size_cap_realistic_fits_and_oversize_is_rejected() {
    let fx = fixture();
    let mut realistic = unsigned_of(&fx.manifest);
    realistic.members = many_members(&fx, MAX_GROUP_MEMBERS, 2, 40);
    for m in &mut realistic.members {
        m.caps = vec![
            format!("group.send:{}", fx.gid),
            format!("group.recv:{}", fx.gid),
            format!("sync.push:{}/notes", fx.gid),
            format!("kv.write:{}", fx.gid),
        ];
    }
    let manifest = resign_root(&fx, realistic);
    let len = manifest.to_wire_bytes().unwrap().len();
    assert!(len < MAX_GROUP_MANIFEST_LEN, "realistic manifest is {len}");
    verify_group_manifest(&manifest, NOW, None).unwrap();

    let mut huge = unsigned_of(&fx.manifest);
    huge.members = many_members(&fx, MAX_GROUP_MEMBERS, 8, 256);
    assert!(matches!(
        sign_group_manifest(huge.clone(), &fx.root.sk),
        Err(CoreError::GroupManifestTooLarge { .. })
    ));
    let raw = GroupManifest {
        v: huge.v,
        group_id: huge.group_id,
        name: huge.name,
        seq: huge.seq,
        min_wire_version: huge.min_wire_version,
        ts: huge.ts,
        expires_at: huge.expires_at,
        root_signing_pub: huge.root_signing_pub,
        signer_device_id: huge.signer_device_id,
        signer_signing_pub: None,
        admin_grant: None,
        members: huge.members,
        revoked_members: huge.revoked_members,
        sig: manifest.sig.clone(),
    };
    assert!(matches!(
        verify_group_manifest(&raw, NOW, None),
        Err(CoreError::GroupManifestTooLarge { .. })
    ));
    let mut book = GroupBook::new();
    assert!(matches!(
        ingest(&mut book, &raw),
        Err(CoreError::GroupManifestTooLarge { .. })
    ));
}

#[test]
fn member_count_is_bounded_at_32() {
    let fx = fixture();
    let mut ok = unsigned_of(&fx.manifest);
    ok.members = many_members(&fx, MAX_GROUP_MEMBERS, 1, 40);
    verify_group_manifest(&resign_root(&fx, ok), NOW, None).unwrap();

    let mut over = unsigned_of(&fx.manifest);
    over.members = many_members(&fx, MAX_GROUP_MEMBERS + 1, 1, 40);
    let err = verify_group_manifest(&resign_root(&fx, over), NOW, None).unwrap_err();
    assert!(invalid_msg(&err).contains("1..=32"));

    let mut empty = unsigned_of(&fx.manifest);
    empty.members.clear();
    assert!(verify_group_manifest(&resign_root(&fx, empty), NOW, None).is_err());
}

#[test]
fn r3_founding_root_must_remain_with_matching_pins() {
    let fx = fixture();
    let peer = Dev::new(3);
    let mut no_root = unsigned_of(&fx.manifest);
    no_root.members = vec![peer.member("peer", std_caps(&fx.gid))];
    let err = verify_group_manifest(&resign_root(&fx, no_root), NOW, None).unwrap_err();
    assert!(invalid_msg(&err).contains("root"));

    let mut bad_relay = unsigned_of(&fx.manifest);
    bad_relay.members[0].relay_pub = peer.member("x", vec![]).relay_pub;
    let err = verify_group_manifest(&resign_root(&fx, bad_relay), NOW, None).unwrap_err();
    assert!(invalid_msg(&err).contains("relay_pub"));

    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let err = remove_member(
        &m2,
        &GroupSigner::root(&fx.root.sk),
        &fx.root.id(),
        &s2,
        params(),
    )
    .unwrap_err();
    assert!(invalid_msg(&err).contains("root"));
}

#[test]
fn co_admin_cannot_remove_root_or_clear_revocations() {
    let (fx, admin, grant, m2, s2) = co_admin_fixture();
    let peer = Dev::new(3);
    let (m3, _s3) = add_member(
        &m2,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &s2,
        params(),
    )
    .unwrap();
    let (m4, _s4) = remove_member(
        &m3,
        &GroupSigner::root(&fx.root.sk),
        &peer.id(),
        &V2GroupSecrets::new(*s2.group_rendezvous_key(), 3),
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    for m in [&fx.manifest, &m2, &m3, &m4] {
        ingest(&mut book, m).unwrap();
    }

    let mut drop_root = unsigned_of(&m4);
    drop_root.seq = 5;
    drop_root.members.retain(|m| m.device_id != fx.root.id());
    drop_root.signer_device_id = admin.id();
    drop_root.signer_signing_pub = Some(admin.sk.public_key().to_b64url());
    drop_root.admin_grant = Some(grant.clone());
    let m = sign_group_manifest(drop_root, &admin.sk).unwrap();
    assert!(invalid_msg(&ingest(&mut book, &m).unwrap_err()).contains("root"));

    let mut clear = unsigned_of(&m4);
    clear.seq = 5;
    clear.revoked_members.clear();
    clear.signer_device_id = admin.id();
    clear.signer_signing_pub = Some(admin.sk.public_key().to_b64url());
    clear.admin_grant = Some(grant);
    let m = sign_group_manifest(clear, &admin.sk).unwrap();
    assert!(ingest(&mut book, &m).is_err());
    assert_eq!(book.manifest(&fx.gid).unwrap().seq, 4);
}

#[test]
fn r4_revoked_set_rules() {
    let fx = fixture();
    let peer = Dev::new(3);
    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let (m3, s3) = remove_member(
        &m2,
        &GroupSigner::root(&fx.root.sk),
        &peer.id(),
        &s2,
        params(),
    )
    .unwrap();
    assert_eq!(m3.revoked_members, vec![peer.id()]);
    assert_ne!(s3.group_rendezvous_key(), s2.group_rendezvous_key());

    assert_eq!(
        add_member(
            &m3,
            &GroupSigner::root(&fx.root.sk),
            peer.member("peer", std_caps(&fx.gid)),
            &s3,
            params()
        )
        .unwrap_err(),
        CoreError::GroupMemberRevoked(peer.id())
    );

    let mut book = GroupBook::new();
    ingest(&mut book, &m3).unwrap();

    let mut readd = unsigned_of(&m3);
    readd.seq = 4;
    readd.members.push(peer.member("peer", std_caps(&fx.gid)));
    assert_eq!(
        ingest(&mut book, &resign_root(&fx, readd.clone())).unwrap_err(),
        CoreError::GroupMemberRevoked(peer.id())
    );

    readd.revoked_members.clear();
    assert_eq!(
        ingest(&mut book, &resign_root(&fx, readd)).unwrap_err(),
        CoreError::GroupMemberRevoked(peer.id())
    );

    let mut omit = unsigned_of(&m3);
    omit.seq = 4;
    omit.revoked_members.clear();
    let err = ingest(&mut book, &resign_root(&fx, omit)).unwrap_err();
    assert!(invalid_msg(&err).contains("superset"));

    let mut dup = unsigned_of(&m3);
    dup.revoked_members.push(peer.id());
    assert!(verify_group_manifest(&resign_root(&fx, dup), NOW, None).is_err());

    let mut many = unsigned_of(&m3);
    many.revoked_members = (0..=MAX_REVOKED_MEMBERS)
        .map(|i| format!("dev_{i:016x}"))
        .collect();
    assert!(verify_group_manifest(&resign_root(&fx, many), NOW, None).is_err());

    let mut dup_member = unsigned_of(&fx.manifest);
    dup_member.members.push(dup_member.members[0].clone());
    assert!(verify_group_manifest(&resign_root(&fx, dup_member), NOW, None).is_err());
}

#[test]
fn r5_member_caps_are_scoped_to_the_group() {
    let fx = fixture();
    let other = format!("group.send:{}", "grp_ffffffffffffffff");
    let bad_caps = [
        "fs.read:/etc/passwd".to_string(),
        other,
        "group.send".to_string(),
        format!("group.admin:{}", fx.gid),
        format!("sync.push:{}*", fx.gid),
        format!("sync.push:{}/../x", fx.gid),
        format!("sync.push:{}//x", fx.gid),
        format!("sync.push:{}/", fx.gid),
        "notacap".to_string(),
    ];
    for cap in bad_caps {
        let mut u = unsigned_of(&fx.manifest);
        u.members[0].caps = vec![cap.clone()];
        let err = verify_group_manifest(&resign_root(&fx, u), NOW, None).unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::InvalidGroupCapabilityScope(_) | CoreError::InvalidCapability(_)
            ),
            "{cap}: {err:?}"
        );
    }
    let mut ok = unsigned_of(&fx.manifest);
    ok.members[0].caps = vec![
        format!("sync.push:{}/wiki", fx.gid),
        format!("sync.push:{}/*", fx.gid),
        format!("kv.write:{}", fx.gid),
    ];
    verify_group_manifest(&resign_root(&fx, ok), NOW, None).unwrap();

    let mut too_many = unsigned_of(&fx.manifest);
    too_many.members[0].caps = (0..17).map(|i| format!("kv.w{i}:{}", fx.gid)).collect();
    assert!(verify_group_manifest(&resign_root(&fx, too_many), NOW, None).is_err());
}

#[test]
fn endpoint_hints_are_validated_and_bounded() {
    let fx = fixture();
    for bad in [
        "http://169.254.169.254/latest".to_string(),
        "wss://user@relay.example/".to_string(),
        "direct:169.254.169.254:80".to_string(),
        "local:/tmp/sock".to_string(),
        "unix:///run/sock".to_string(),
        format!("wss://relay.example/{}", "a".repeat(260)),
    ] {
        let mut u = unsigned_of(&fx.manifest);
        u.members[0].endpoints = vec![bad.clone()];
        assert!(
            verify_group_manifest(&resign_root(&fx, u), NOW, None).is_err(),
            "{bad}"
        );
    }
    let mut u = unsigned_of(&fx.manifest);
    u.members[0].endpoints = (0..9)
        .map(|i| format!("wss://relay{i}.example/v2/relay"))
        .collect();
    assert!(verify_group_manifest(&resign_root(&fx, u), NOW, None).is_err());
}

#[test]
fn r5_co_admin_requires_a_valid_root_admin_grant() {
    let (fx, admin, grant, m2, s2) = co_admin_fixture();
    let signer = GroupSigner::co_admin(&admin.sk, admin.id(), grant.clone());
    let peer = Dev::new(3);
    let (m3, _) = add_member(
        &m2,
        &signer,
        peer.member("peer", std_caps(&fx.gid)),
        &s2,
        params(),
    )
    .unwrap();
    assert!(
        verify_group_manifest(&m3, NOW, None)
            .unwrap()
            .signed_by_co_admin()
    );

    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    assert_eq!(
        book.ingest_group_manifest(&m3, NOW, None)
            .unwrap()
            .newly_joined,
        vec![peer.id()]
    );

    let mut no_grant = unsigned_of(&m3);
    no_grant.admin_grant = None;
    let m = sign_group_manifest(no_grant, &admin.sk).unwrap();
    assert!(matches!(
        verify_group_manifest(&m, NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));

    let mut no_key = unsigned_of(&m3);
    no_key.signer_signing_pub = None;
    let m = sign_group_manifest(no_key, &admin.sk).unwrap();
    assert!(verify_group_manifest(&m, NOW, None).is_err());

    let mut root_with_grant = unsigned_of(&fx.manifest);
    root_with_grant.admin_grant = Some(grant.clone());
    assert!(verify_group_manifest(&resign_root(&fx, root_with_grant), NOW, None).is_err());

    // Grant for a different subject.
    let stranger = Dev::new(4);
    let other_grant = issue_admin_grant(
        &fx.root.sk,
        &fx.root.id(),
        &fx.gid,
        &stranger.id(),
        stranger.sk.public_key(),
        0,
        params(),
    )
    .unwrap();
    let mut wrong_subject = unsigned_of(&m3);
    wrong_subject.admin_grant = Some(other_grant);
    let m = sign_group_manifest(wrong_subject, &admin.sk).unwrap();
    assert!(matches!(
        verify_group_manifest(&m, NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));

    // Signer key not matching its member entry.
    let mut wrong_key = unsigned_of(&m3);
    wrong_key.signer_signing_pub = Some(stranger.sk.public_key().to_b64url());
    let m = sign_group_manifest(wrong_key, &stranger.sk).unwrap();
    assert!(verify_group_manifest(&m, NOW, None).is_err());

    // Signer not a member.
    let mut not_member = unsigned_of(&m3);
    not_member.members.retain(|m| m.device_id != admin.id());
    let m = sign_group_manifest(not_member, &admin.sk).unwrap();
    assert!(invalid_msg(&verify_group_manifest(&m, NOW, None).unwrap_err()).contains("signer"));

    // Grant self-issued by the co-admin instead of the root.
    let forged = tendril_core::grants::sign_grant(
        tendril_core::grants::GrantUnsigned {
            v: 1,
            issuer: admin.id(),
            subject: admin.id(),
            caps: vec![format!("group.admin:{}", fx.gid)],
            not_before: grant.not_before.clone(),
            not_after: grant.not_after.clone(),
            nonce: "forged".to_string(),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        &admin.sk,
    )
    .unwrap();
    let mut forged_u = unsigned_of(&m3);
    forged_u.admin_grant = Some(forged);
    let m = sign_group_manifest(forged_u, &admin.sk).unwrap();
    assert!(matches!(
        verify_group_manifest(&m, NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
}

#[test]
fn admin_grant_scope_expiry_crl_and_delegation() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let mk = |g: tendril_core::grants::Grant| {
        let mut u = unsigned_of(&m2);
        u.seq = 3;
        u.signer_device_id = admin.id();
        u.signer_signing_pub = Some(admin.sk.public_key().to_b64url());
        u.admin_grant = Some(g);
        sign_group_manifest(u, &admin.sk).unwrap()
    };
    verify_group_manifest(&mk(grant.clone()), NOW, None).unwrap();

    // Wrong group scope.
    let wrong_cap = sign_grant(
        tendril_core::grants::GrantUnsigned {
            caps: vec!["group.admin:grp_ffffffffffffffff".to_string()],
            ..grant_unsigned(&grant)
        },
        &fx.root.sk,
    )
    .unwrap();
    assert!(matches!(
        verify_group_manifest(&mk(wrong_cap), NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));

    // Not-yet-valid and expired windows.
    let early = sign_grant(
        tendril_core::grants::GrantUnsigned {
            not_before: "2026-12-30T00:00:00Z".to_string(),
            not_after: "2027-01-30T00:00:00Z".to_string(),
            ..grant_unsigned(&grant)
        },
        &fx.root.sk,
    )
    .unwrap();
    assert!(verify_group_manifest(&mk(early), NOW, None).is_err());
    let expired = sign_grant(
        tendril_core::grants::GrantUnsigned {
            not_before: "2026-10-01T00:00:00Z".to_string(),
            not_after: "2026-11-01T00:00:00Z".to_string(),
            ..grant_unsigned(&grant)
        },
        &fx.root.sk,
    )
    .unwrap();
    assert!(verify_group_manifest(&mk(expired), NOW, None).is_err());

    // Delegated (non-root-direct) grants are refused.
    let delegated = sign_grant(
        tendril_core::grants::GrantUnsigned {
            issuer: fx.root.id(),
            delegated_from: vec![grant.clone()],
            ..grant_unsigned(&grant)
        },
        &fx.root.sk,
    )
    .unwrap();
    assert!(verify_group_manifest(&mk(delegated), NOW, None).is_err());

    // Root CRL revoking the co-admin or the grant nonce.
    let crl_for = |devices: Vec<String>, nonces: Vec<String>| {
        sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: fx.root.id(),
                seq: 1,
                revoked_devices: devices,
                revoked_nonces: nonces,
                ts: "2026-11-25T00:00:00Z".to_string(),
            },
            &fx.root.sk,
        )
        .unwrap()
    };
    let m = mk(grant.clone());
    let via_resolver = |list| resolved_at(&fx, &fx.root.id(), list).unwrap();
    let clean = via_resolver(crl_for(vec![], vec![]));
    verify_group_manifest(&m, NOW, Some(&clean)).unwrap();
    let by_device = via_resolver(crl_for(vec![admin.id()], vec![]));
    assert!(matches!(
        verify_group_manifest(&m, NOW, Some(&by_device)),
        Err(CoreError::GroupUnauthorized(_))
    ));
    let by_nonce = via_resolver(crl_for(vec![], vec![grant.nonce.clone()]));
    assert!(matches!(
        verify_group_manifest(&m, NOW, Some(&by_nonce)),
        Err(CoreError::GroupUnauthorized(_))
    ));
}

fn grant_unsigned(g: &tendril_core::grants::Grant) -> tendril_core::grants::GrantUnsigned {
    g.unsigned()
}

#[test]
fn co_admin_limit_is_enforced_by_the_builder_only() {
    let fx = fixture();
    assert!(
        issue_admin_grant(
            &fx.root.sk,
            &fx.root.id(),
            &fx.gid,
            "dev_0000000000000001",
            fx.root.sk.public_key(),
            MAX_GROUP_CO_ADMINS - 1,
            params()
        )
        .is_ok()
    );
    assert!(matches!(
        issue_admin_grant(
            &fx.root.sk,
            &fx.root.id(),
            &fx.gid,
            "dev_0000000000000001",
            fx.root.sk.public_key(),
            MAX_GROUP_CO_ADMINS,
            params()
        ),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(
        issue_admin_grant(
            &fx.root.sk,
            &fx.root.id(),
            "grp_ffffffffffffffff",
            "dev_0000000000000001",
            fx.root.sk.public_key(),
            0,
            params()
        )
        .is_err()
    );
}

#[test]
fn r6_time_rules() {
    let fx = fixture();
    let ts = NOW;
    let mk = |ts_s: &str, exp: &str| {
        let mut u = unsigned_of(&fx.manifest);
        u.ts = ts_s.to_string();
        u.expires_at = exp.to_string();
        resign_root(&fx, u)
    };
    // 2026-11-25T00:00:00Z + 90d = 2027-02-23T00:00:00Z
    verify_group_manifest(
        &mk("2026-11-25T00:00:00Z", "2027-02-23T00:00:00Z"),
        ts,
        None,
    )
    .unwrap();
    assert!(
        verify_group_manifest(
            &mk("2026-11-25T00:00:00Z", "2027-02-23T00:00:01Z"),
            ts,
            None
        )
        .is_err()
    );
    assert!(
        verify_group_manifest(
            &mk("2026-11-25T00:00:00Z", "2026-11-25T00:00:00Z"),
            ts,
            None
        )
        .is_err()
    );
    assert!(
        verify_group_manifest(
            &mk("2026-11-25T00:00:00Z", "2026-11-24T00:00:00Z"),
            ts,
            None
        )
        .is_err()
    );
    assert!(
        verify_group_manifest(
            &mk("2026-11-25T00:00:00.000Z", "2026-12-25T00:00:00Z"),
            ts,
            None
        )
        .is_err()
    );
    assert!(
        verify_group_manifest(
            &mk("2026-11-25T00:00:00+00:00", "2026-12-25T00:00:00Z"),
            ts,
            None
        )
        .is_err()
    );
    // Future ts beyond 30 s skew.
    let future = mk("2026-11-25T00:01:00Z", "2026-12-25T00:00:00Z");
    assert!(verify_group_manifest(&future, ts, None).is_err());
    let skewed = mk("2026-11-25T00:00:30Z", "2026-12-25T00:00:00Z");
    verify_group_manifest(&skewed, ts, None).unwrap();

    let expires = NOW + DEFAULT_MANIFEST_VALIDITY_SECS;
    assert!(verify_group_manifest(&fx.manifest, expires - 1, None).is_ok());
    assert!(verify_group_manifest(&fx.manifest, expires, None).is_err());
    assert!(
        GroupBuildParams::new(NOW)
            .with_validity_secs(MAX_MANIFEST_VALIDITY_SECS + 1)
            .validity_secs
            > MAX_MANIFEST_VALIDITY_SECS
    );
    assert!(
        tendril_core::group::renew_manifest(
            &fx.manifest,
            &GroupSigner::root(&fx.root.sk),
            &fx.secrets,
            GroupBuildParams::new(NOW).with_validity_secs(MAX_MANIFEST_VALIDITY_SECS + 1)
        )
        .is_err()
    );
}

#[test]
fn stored_manifest_that_expires_stays_stored_but_fails_closed() {
    let fx = fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    let send = Capability::parse(&format!("group.send:{}", fx.gid)).unwrap();
    book.authorize_group(&fx.gid, &fx.root.id(), &send, NOW, None)
        .unwrap();
    let late = NOW + DEFAULT_MANIFEST_VALIDITY_SECS;
    assert!(matches!(
        book.authorize_group(&fx.gid, &fx.root.id(), &send, late, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(book.manifest(&fx.gid).is_some());
    assert!(matches!(
        book.ingest_group_manifest(&fx.manifest, late, None),
        Err(CoreError::InvalidGroupManifest(_))
    ));
}

#[test]
fn r7_wire_floor_is_non_decreasing() {
    let fx = fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    let mut down = unsigned_of(&fx.manifest);
    down.seq = 2;
    down.min_wire_version = 1;
    assert_eq!(
        ingest(&mut book, &resign_root(&fx, down)).unwrap_err(),
        CoreError::GroupWireDowngrade { current: 2, got: 1 }
    );
    assert_eq!(
        set_min_wire_version(
            &fx.manifest,
            &GroupSigner::root(&fx.root.sk),
            1,
            &fx.secrets,
            params()
        )
        .unwrap_err(),
        CoreError::GroupWireDowngrade { current: 2, got: 1 }
    );
    for bad in [0u8, 3] {
        let mut u = unsigned_of(&fx.manifest);
        u.min_wire_version = bad;
        assert!(verify_group_manifest(&resign_root(&fx, u), NOW, None).is_err());
    }
}

#[test]
fn builders_raise_floor_and_renew() {
    let root = Dev::new(1);
    let gid = group_id_from_root(root.sk.public_key());
    let (m1, s1) = tendril_core::group::create_group(
        &root.sk,
        "g",
        1,
        root.member("root", std_caps(&gid)),
        params(),
    )
    .unwrap();
    let (m2, s2) =
        set_min_wire_version(&m1, &GroupSigner::root(&root.sk), 2, &s1, params()).unwrap();
    assert_eq!(m2.min_wire_version, 2);
    let (m3, s3) = renew_manifest(
        &m2,
        &GroupSigner::root(&root.sk),
        &s2,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap();
    assert_eq!(m3.seq, 3);
    assert_eq!(s3.group_rendezvous_key(), s1.group_rendezvous_key());
    let mut book = GroupBook::new();
    for m in [&m1, &m2, &m3] {
        ingest(&mut book, m).unwrap();
    }
    assert!(
        add_member(
            &m1,
            &GroupSigner::root(&root.sk),
            root.member("dup", std_caps(&gid)),
            &s1,
            params()
        )
        .is_err()
    );
    assert!(
        add_member(
            &m3,
            &GroupSigner::root(&root.sk),
            Dev::new(5).member("x", std_caps(&gid)),
            &s1,
            params()
        )
        .is_err()
    );
}

#[test]
fn authorize_group_checks_membership_caps_and_admin() {
    let (fx, admin, grant, m2, s2) = co_admin_fixture();
    let reader = Dev::new(3);
    let mut reader_member = reader.member("reader", vec![format!("group.recv:{}", fx.gid)]);
    reader_member
        .caps
        .push(format!("sync.push:{}/wiki/*", fx.gid));
    let (m3, _s3) = add_member(
        &m2,
        &GroupSigner::co_admin(&admin.sk, admin.id(), grant),
        reader_member,
        &s2,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m3).unwrap();
    let cap = |s: &str| Capability::parse(s).unwrap();
    let gid = &fx.gid;

    book.authorize_group(
        gid,
        &reader.id(),
        &cap(&format!("group.recv:{gid}")),
        NOW,
        None,
    )
    .unwrap();
    book.authorize_group(
        gid,
        &reader.id(),
        &cap(&format!("sync.push:{gid}/wiki/page")),
        NOW,
        None,
    )
    .unwrap();
    assert!(matches!(
        book.authorize_group(
            gid,
            &reader.id(),
            &cap(&format!("group.send:{gid}")),
            NOW,
            None
        ),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(matches!(
        book.authorize_group(
            gid,
            &reader.id(),
            &cap(&format!("sync.push:{gid}/other")),
            NOW,
            None
        ),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(matches!(
        book.authorize_group(gid, &reader.id(), &cap("fs.read:/etc/passwd"), NOW, None),
        Err(CoreError::InvalidGroupCapabilityScope(_))
    ));
    assert!(matches!(
        book.authorize_group(
            gid,
            &reader.id(),
            &cap("group.recv:grp_ffffffffffffffff"),
            NOW,
            None
        ),
        Err(CoreError::InvalidGroupCapabilityScope(_))
    ));
    assert!(matches!(
        book.authorize_group(
            gid,
            "dev_0000000000000009",
            &cap(&format!("group.send:{gid}")),
            NOW,
            None
        ),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(matches!(
        book.authorize_group(
            "grp_ffffffffffffffff",
            &reader.id(),
            &cap("group.recv:grp_ffffffffffffffff"),
            NOW,
            None
        ),
        Err(CoreError::GroupNotFound(_))
    ));

    let admin_cap = cap(&format!("group.admin:{gid}"));
    book.authorize_group(gid, &fx.root.id(), &admin_cap, NOW, None)
        .unwrap();
    book.authorize_group(gid, &admin.id(), &admin_cap, NOW, None)
        .unwrap();
    assert!(matches!(
        book.authorize_group(gid, &reader.id(), &admin_cap, NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));

    let (m4, _) = remove_member(
        &m3,
        &GroupSigner::root(&fx.root.sk),
        &reader.id(),
        &V2GroupSecrets::new(*s2.group_rendezvous_key(), 3),
        params(),
    )
    .unwrap();
    ingest(&mut book, &m4).unwrap();
    assert_eq!(
        book.authorize_group(
            gid,
            &reader.id(),
            &cap(&format!("group.recv:{gid}")),
            NOW,
            None
        ),
        Err(CoreError::GroupMemberRevoked(reader.id()))
    );
}

#[test]
fn r8_rendezvous_accepted_only_from_admins_at_the_stored_seq() {
    let (fx, admin, grant, m2, s2) = co_admin_fixture();
    let member = Dev::new(3);
    let signer = GroupSigner::co_admin(&admin.sk, admin.id(), grant);
    let (m3, s3) = add_member(
        &m2,
        &signer,
        member.member("m", std_caps(&fx.gid)),
        &s2,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m3).unwrap();
    let frame = s3.to_rendezvous_frame(&fx.gid).unwrap();
    assert_eq!(frame.len(), GROUP_RENDEZVOUS_FRAME_LEN);

    assert!(matches!(
        book.ingest_group_rendezvous(&member.id(), &frame[..], NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(matches!(
        book.ingest_group_rendezvous("dev_0000000000000009", &frame[..], NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(book.secrets(&fx.gid).is_none());
    book.ingest_group_rendezvous(&fx.root.id(), &frame[..], NOW, None)
        .unwrap();
    assert_eq!(book.secrets(&fx.gid), Some(&s3));
    book.ingest_group_rendezvous(&admin.id(), &frame[..], NOW, None)
        .unwrap();

    let stale = encode_group_rendezvous_frame(&fx.gid, 2, &[7u8; 32]).unwrap();
    assert_eq!(
        book.ingest_group_rendezvous(&fx.root.id(), &stale[..], NOW, None),
        Err(CoreError::GroupSeqRollback { current: 3, got: 2 })
    );
    let ahead = encode_group_rendezvous_frame(&fx.gid, 4, &[7u8; 32]).unwrap();
    assert!(
        book.ingest_group_rendezvous(&fx.root.id(), &ahead[..], NOW, None)
            .is_err()
    );
    let conflicting = encode_group_rendezvous_frame(&fx.gid, 3, &[7u8; 32]).unwrap();
    assert!(
        book.ingest_group_rendezvous(&fx.root.id(), &conflicting[..], NOW, None)
            .is_err()
    );
    let unknown = encode_group_rendezvous_frame("grp_ffffffffffffffff", 3, &[7u8; 32]).unwrap();
    assert!(matches!(
        book.ingest_group_rendezvous(&fx.root.id(), &unknown[..], NOW, None),
        Err(CoreError::GroupNotFound(_))
    ));

    // A later root-signed manifest demotes the co-admin: only the root may deliver keys.
    let (m4, s4) = renew_manifest(&m3, &GroupSigner::root(&fx.root.sk), &s3, params()).unwrap();
    ingest(&mut book, &m4).unwrap();
    let frame4 = s4.to_rendezvous_frame(&fx.gid).unwrap();
    assert!(matches!(
        book.ingest_group_rendezvous(&admin.id(), &frame4[..], NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    book.ingest_group_rendezvous(&fx.root.id(), &frame4[..], NOW, None)
        .unwrap();
}

#[test]
fn rendezvous_frame_codec_is_exactly_60_bytes() {
    let key = [0xAB; 32];
    let frame =
        encode_group_rendezvous_frame("grp_0123456789abcdef", 0x0001_0203_0405_0607, &key).unwrap();
    assert_eq!(frame.len(), 60);
    assert_eq!(&frame[..20], b"grp_0123456789abcdef");
    assert_eq!(&frame[20..28], &[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(&frame[28..], &key);
    let decoded = decode_group_rendezvous_frame(&frame[..]).unwrap();
    assert_eq!(decoded.group_id, "grp_0123456789abcdef");
    assert_eq!(decoded.seq, 0x0001_0203_0405_0607);
    assert_eq!(decoded.group_rendezvous_key(), &key);
    assert!(format!("{decoded:?}").contains("redacted"));
    for len in [0usize, 59, 61, 100] {
        assert!(decode_group_rendezvous_frame(&vec![b'g'; len]).is_err());
    }
    let mut bad_id = frame.to_vec();
    bad_id[4] = b'G';
    assert!(decode_group_rendezvous_frame(&bad_id).is_err());
    assert!(encode_group_rendezvous_frame("grp_short", 1, &key).is_err());
}

#[test]
fn bootstrap_and_mailbox_derivations() {
    let key = [0x11; 32];
    let a = "dev_aaaaaaaaaaaaaaaa";
    let b = "dev_bbbbbbbbbbbbbbbb";
    let ab = derive_pair_bootstrap(&key, 7, a, b);
    assert_eq!(*ab, *derive_pair_bootstrap(&key, 7, b, a));
    assert_ne!(*ab, *derive_pair_bootstrap(&key, 8, a, b));
    assert_ne!(*ab, *derive_pair_bootstrap(&[0x12; 32], 7, a, b));
    assert_ne!(
        *ab,
        *derive_pair_bootstrap(&key, 7, a, "dev_cccccccccccccccc")
    );

    let mut info = b"tendril-group-v2-rendezvous\0".to_vec();
    info.extend_from_slice(a.as_bytes());
    info.push(0);
    info.extend_from_slice(b.as_bytes());
    assert_eq!(
        *ab,
        *tendril_core::crypto::hkdf_sha256_32(&key, &7u64.to_be_bytes(), &info)
    );

    let mb = derive_group_mailbox_secret(&key, 7, a);
    let mut minfo = b"tendril-group-v2-mailbox".to_vec();
    minfo.extend_from_slice(a.as_bytes());
    assert_eq!(
        *mb,
        *tendril_core::crypto::hkdf_sha256_32(&key, &7u64.to_be_bytes(), &minfo)
    );
    assert_ne!(*mb, *derive_group_mailbox_secret(&key, 7, b));
}

#[test]
fn book_pair_bootstrap_requires_active_members_and_current_key() {
    let fx = fixture();
    let peer = Dev::new(3);
    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("p", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    assert!(
        book.pair_bootstrap(&fx.gid, &fx.root.id(), &peer.id(), NOW)
            .is_err()
    );
    assert!(book.install_secrets(&fx.gid, fx.secrets.clone()).is_err());
    book.install_secrets(&fx.gid, s2.clone()).unwrap();
    let derived = book
        .pair_bootstrap(&fx.gid, &peer.id(), &fx.root.id(), NOW)
        .unwrap();
    assert_eq!(
        *derived,
        *derive_pair_bootstrap(s2.group_rendezvous_key(), 2, &fx.root.id(), &peer.id())
    );
    assert!(
        book.pair_bootstrap(&fx.gid, &fx.root.id(), "dev_0000000000000009", NOW)
            .is_err()
    );
}

#[test]
fn book_serde_roundtrip_and_integrity() {
    let fx = fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    book.install_secrets(&fx.gid, fx.secrets.clone()).unwrap();
    let json = serde_json::to_string(&book).unwrap();
    assert!(!json.contains(&b64url_encode(&[0u8; 0])) || json.contains("group_rendezvous_key"));
    let back: GroupBook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, book);
    assert_eq!(
        back.gossip_summary(),
        vec![GroupSeq {
            group_id: fx.gid.clone(),
            seq: 1
        }]
    );
    let debug = format!("{:?}", fx.secrets);
    assert!(debug.contains("redacted"));

    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let rec = v["groups"][&fx.gid].clone();
    v["groups"]["grp_ffffffffffffffff"] = rec;
    assert!(serde_json::from_value::<GroupBook>(v).is_err());
}

#[test]
fn gossip_summary_is_capped_at_16_groups() {
    let mut book = GroupBook::new();
    for i in 0..(MAX_GOSSIP_GROUPS + 4) {
        let root = Dev::new(100 + u8::try_from(i).unwrap());
        let gid = group_id_from_root(root.sk.public_key());
        let (m, _) = tendril_core::group::create_group(
            &root.sk,
            "g",
            2,
            root.member("r", std_caps(&gid)),
            params(),
        )
        .unwrap();
        ingest(&mut book, &m).unwrap();
    }
    assert_eq!(book.gossip_summary().len(), MAX_GOSSIP_GROUPS);
    assert_eq!(book.group_ids().len(), MAX_GOSSIP_GROUPS + 4);
}

#[test]
fn session_hello_groups_field_rules() {
    let base = SessionHello {
        device_id: "dev_0123456789abcdef".to_string(),
        grant: None,
        crl_seq: None,
        groups: None,
        route_seq: None,
        upgrade: Vec::new(),
    };
    let json = serde_json::to_string(&base).unwrap();
    assert!(!json.contains("groups"));
    let empty = SessionHello {
        groups: Some(vec![]),
        ..base.clone()
    };
    assert!(!serde_json::to_string(&empty).unwrap().contains("groups"));

    let with = SessionHello {
        groups: Some(vec![GroupSeq {
            group_id: "grp_0123456789abcdef".to_string(),
            seq: 3,
        }]),
        ..base.clone()
    };
    let text = serde_json::to_string(&with).unwrap();
    assert_eq!(serde_json::from_str::<SessionHello>(&text).unwrap(), with);

    let parse = |groups: serde_json::Value| {
        serde_json::from_value::<SessionHello>(serde_json::json!({
            "device_id": "dev_0123456789abcdef",
            "groups": groups
        }))
    };
    assert!(parse(serde_json::json!([])).is_err());
    assert!(parse(serde_json::json!(null)).is_err());
    assert!(parse(serde_json::json!([{"group_id": "grp_XYZ", "seq": 1}])).is_err());
    assert!(parse(serde_json::json!([{"group_id": "grp_0123456789ABCDEF", "seq": 1}])).is_err());
    assert!(parse(serde_json::json!([{"group_id": "grp_0123456789abcdef", "seq": 0}])).is_err());
    assert!(
        parse(serde_json::json!([{"group_id": "grp_0123456789abcdef", "seq": 1, "x": 1}])).is_err()
    );
    let dup = serde_json::json!([
        {"group_id": "grp_0123456789abcdef", "seq": 1},
        {"group_id": "grp_0123456789abcdef", "seq": 2}
    ]);
    assert!(parse(dup).is_err());
    let many: Vec<_> = (0..17)
        .map(|i| serde_json::json!({"group_id": format!("grp_{i:016x}"), "seq": 1}))
        .collect();
    assert!(parse(serde_json::Value::Array(many)).is_err());
    let max: Vec<_> = (0..16)
        .map(|i| serde_json::json!({"group_id": format!("grp_{i:016x}"), "seq": 1}))
        .collect();
    assert!(parse(serde_json::Value::Array(max)).is_ok());
}

#[test]
fn inner_frame_codec_enforces_size_bounds() {
    assert_eq!(
        InnerFrameType::try_from(0x0A).unwrap(),
        InnerFrameType::GroupManifest
    );
    assert_eq!(
        InnerFrameType::try_from(0x0B).unwrap(),
        InnerFrameType::GroupRendezvous
    );
    assert_eq!(
        InnerFrameType::try_from(0x0C).unwrap(),
        InnerFrameType::RouteSet
    );
    assert_eq!(
        InnerFrameType::try_from(0x0D).unwrap(),
        InnerFrameType::PathUpgrade
    );
    assert_eq!(
        InnerFrameType::try_from(0x0E),
        Err(CoreError::UnknownInnerFrameType(0x0E))
    );

    let ok = vec![b'{'; MAX_GROUP_MANIFEST_LEN];
    let enc = encode_inner_frame(InnerFrameType::GroupManifest, &ok).unwrap();
    assert_eq!(enc[0], 0x0A);
    assert_eq!(
        decode_inner_frame(&enc).unwrap().0,
        InnerFrameType::GroupManifest
    );
    let over = vec![b'{'; MAX_GROUP_MANIFEST_LEN + 1];
    assert!(matches!(
        encode_inner_frame(InnerFrameType::GroupManifest, &over),
        Err(CoreError::GroupManifestTooLarge { .. })
    ));
    let mut raw = vec![0x0A];
    raw.extend_from_slice(&over);
    assert!(matches!(
        decode_inner_frame(&raw),
        Err(CoreError::GroupManifestTooLarge { .. })
    ));

    for len in [0usize, 59, 61] {
        assert!(encode_inner_frame(InnerFrameType::GroupRendezvous, &vec![0; len]).is_err());
    }
    assert!(encode_inner_frame(InnerFrameType::GroupRendezvous, &[0; 60]).is_ok());
}

#[test]
fn padded_envelope_carries_group_frames() {
    let policy = PaddingPolicy::v2_default();
    let payload = vec![b'x'; MAX_GROUP_MANIFEST_LEN];
    let padded = pad_inner_frame(InnerFrameType::GroupManifest, &payload, &policy).unwrap();
    assert_eq!(padded[0], InnerFrameType::Padded as u8);
    assert_eq!(
        decode_v2_inner_frame(&padded, false).unwrap(),
        V2InnerFrame::Frame {
            kind: InnerFrameType::GroupManifest,
            payload: zeroize::Zeroizing::new(payload)
        }
    );
    let rv = pad_inner_frame(InnerFrameType::GroupRendezvous, &[3; 60], &policy).unwrap();
    assert!(matches!(
        decode_v2_inner_frame(&rv, false).unwrap(),
        V2InnerFrame::Frame {
            kind: InnerFrameType::GroupRendezvous,
            ..
        }
    ));
    assert!(pad_inner_frame(InnerFrameType::GroupRendezvous, &[3; 59], &policy).is_err());
    assert!(
        pad_inner_frame(
            InnerFrameType::GroupManifest,
            &vec![0; MAX_GROUP_MANIFEST_LEN + 1],
            &policy
        )
        .is_err()
    );
}

fn v1_pair() -> (EndpointIdentity, EndpointIdentity, Roster, Roster) {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    );
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd".into(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("abcd"))
        .unwrap();
    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    (host, cli, host_roster, cli_roster)
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

#[test]
fn v1_session_surfaces_group_frames_and_hello_groups() {
    let fx = fixture();
    let (host, cli, mut host_roster, mut cli_roster) = v1_pair();
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let summary = vec![GroupSeq {
        group_id: fx.gid.clone(),
        seq: 1,
    }];
    init.set_local_groups(summary.clone()).unwrap();
    assert!(
        init.set_local_groups(vec![GroupSeq {
            group_id: "bad".into(),
            seq: 1
        }])
        .is_err()
    );
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();

    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    let m3 = v1_bytes(init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, NOW, 3, &mut host_roster).unwrap();
    assert_eq!(resp.peer_groups(), Some(&summary[..]));

    let wire = v1_bytes(init.send_group_manifest(&fx.manifest, 10).unwrap());
    let acts = resp.feed_bytes(&wire, NOW, 11, &mut host_roster).unwrap();
    assert_eq!(
        acts,
        vec![SessionAction::GroupManifestReceived(Box::new(
            fx.manifest.clone()
        ))]
    );

    let frame = fx.secrets.to_rendezvous_frame(&fx.gid).unwrap();
    let wire = v1_bytes(init.send_group_rendezvous(&frame[..], 12).unwrap());
    let acts = resp.feed_bytes(&wire, NOW, 13, &mut host_roster).unwrap();
    match &acts[..] {
        [SessionAction::GroupRendezvousReceived(f)] => {
            assert_eq!(f.secrets(), fx.secrets);
        }
        other => panic!("unexpected actions {other:?}"),
    }
    assert!(init.send_group_rendezvous(&[0u8; 59], 14).is_err());

    let mut junk = fx.manifest.clone();
    junk.sig = "x".repeat(10);
    let wire = v1_bytes(init.send_group_manifest(&junk, 15).unwrap());
    let acts = resp.feed_bytes(&wire, NOW, 16, &mut host_roster).unwrap();
    assert!(matches!(
        &acts[..],
        [SessionAction::GroupManifestReceived(_)]
    ));
}

#[test]
fn v2_session_surfaces_group_frames_and_hello_groups() {
    let fx = fixture();
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    );
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    let secrets = V2PeerSecrets::new([0x66; 32], [0x77; 32]);
    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd".into(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("abcd"))
        .unwrap();
    host_roster
        .set_peer_v2_secrets(&cli.device_id(), secrets.clone())
        .unwrap();
    host_roster
        .set_peer_min_wire_version(&cli.device_id(), 2)
        .unwrap();
    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    cli_roster
        .set_peer_v2_secrets(host.host_id(), secrets.clone())
        .unwrap();
    cli_roster
        .set_peer_min_wire_version(host.host_id(), 2)
        .unwrap();

    let mut init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let summary = vec![GroupSeq {
        group_id: fx.gid.clone(),
        seq: 1,
    }];
    init.set_local_groups(summary.clone()).unwrap();
    let mut resp = V2SessionResponder::new(&host).unwrap();

    let m1 = v2_bytes(init.start(NOW).unwrap());
    let m2 = v2_bytes(resp.feed_bytes(&m1, NOW, 10, &mut host_roster).unwrap());
    let m3 = v2_bytes(init.feed_bytes(&m2, NOW, 20, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, NOW, 30, &mut host_roster).unwrap();
    assert_eq!(resp.peer_groups(), Some(&summary[..]));

    let wire = v2_bytes(init.seal_group_manifest(&fx.manifest, 40).unwrap());
    let acts = resp.feed_bytes(&wire, NOW, 41, &mut host_roster).unwrap();
    assert_eq!(
        acts,
        vec![V2SessionAction::GroupManifestReceived(Box::new(
            fx.manifest.clone()
        ))]
    );

    let frame = fx.secrets.to_rendezvous_frame(&fx.gid).unwrap();
    let wire = v2_bytes(resp.seal_group_rendezvous(&frame[..], 50).unwrap());
    let acts = init.feed_bytes(&wire, NOW, 51, &mut cli_roster).unwrap();
    assert!(matches!(
        &acts[..],
        [V2SessionAction::GroupRendezvousReceived(_)]
    ));
    assert!(resp.seal_group_rendezvous(&[0u8; 61], 52).is_err());
    let wire = v2_bytes(resp.seal_group_manifest(&fx.manifest, 53).unwrap());
    let acts = init.feed_bytes(&wire, NOW, 54, &mut cli_roster).unwrap();
    assert!(matches!(
        &acts[..],
        [V2SessionAction::GroupManifestReceived(_)]
    ));
}

#[test]
fn signed_bytes_use_domain_prefix_and_jcs() {
    let fx = fixture();
    let unsigned = unsigned_of(&fx.manifest);
    let bytes = group_manifest_signed_bytes(&unsigned).unwrap();
    assert!(bytes.starts_with(b"tendril-group-v1\0"));
    assert_eq!(&bytes[17..], canonical_json(&unsigned).unwrap().as_bytes());
    assert!(!String::from_utf8_lossy(&bytes[17..]).contains("signer_signing_pub"));
    assert!(!String::from_utf8_lossy(&bytes[17..]).contains("\"sig\""));
    let pk = HybridSigningPublicKey::from_b64url(&fx.manifest.root_signing_pub).unwrap();
    assert_eq!(&pk, fx.root.sk.public_key());
    let _ = x25519_public_from_scalar(&[1u8; 32]);
}

fn crl_for(
    fx: &Fixture,
    devices: Vec<String>,
    nonces: Vec<String>,
) -> tendril_core::grants::RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: fx.root.id(),
            seq: 1,
            revoked_devices: devices,
            revoked_nonces: nonces,
            ts: "2026-11-25T00:00:00Z".to_string(),
        },
        &fx.root.sk,
    )
    .unwrap()
}

fn co_signed(
    base: &GroupManifest,
    signer: &Dev,
    grant: &tendril_core::grants::Grant,
    edit: impl FnOnce(&mut GroupManifestUnsigned),
) -> GroupManifest {
    let mut u = base.unsigned();
    u.seq = base.seq + 1;
    u.signer_device_id = signer.id();
    u.signer_signing_pub = Some(signer.sk.public_key().to_b64url());
    u.admin_grant = Some(grant.clone());
    edit(&mut u);
    sign_group_manifest(u, &signer.sk).unwrap()
}

#[test]
fn a1_admin_grant_is_bound_to_the_signer_key() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let keyed = format!(
        "group.admin:{}/{}",
        fx.gid,
        hex::encode(admin.sk.public_key().sha256_hash())
    );
    assert_eq!(grant.caps, vec![keyed]);
    verify_group_manifest(&co_signed(&m2, &admin, &grant, |_| {}), NOW, None).unwrap();

    // A bare group.admin grant no longer authorizes co-signing.
    let bare = sign_grant(
        tendril_core::grants::GrantUnsigned {
            caps: vec![format!("group.admin:{}", fx.gid)],
            ..grant_unsigned(&grant)
        },
        &fx.root.sk,
    )
    .unwrap();
    assert!(matches!(
        verify_group_manifest(&co_signed(&m2, &admin, &bare, |_| {}), NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));

    // A wildcard does not broaden the keyed capability.
    let wildcard = sign_grant(
        tendril_core::grants::GrantUnsigned {
            caps: vec![format!("group.admin:{}/*", fx.gid)],
            ..grant_unsigned(&grant)
        },
        &fx.root.sk,
    )
    .unwrap();
    assert!(verify_group_manifest(&co_signed(&m2, &admin, &wildcard, |_| {}), NOW, None).is_err());

    // A grant keyed to another signing key is rejected.
    let other = Dev::new(9);
    let wrong_key = issue_admin_grant(
        &fx.root.sk,
        &fx.root.id(),
        &fx.gid,
        &admin.id(),
        other.sk.public_key(),
        0,
        params(),
    )
    .unwrap();
    assert!(verify_group_manifest(&co_signed(&m2, &admin, &wrong_key, |_| {}), NOW, None).is_err());
}

#[test]
fn a1_forged_co_admin_reusing_a_real_grant_with_a_swapped_key_is_rejected() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let attacker = Dev::new(9);
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    let forged_member = GroupMember::new(
        admin.st.public_bytes(),
        "admin",
        attacker.sk.public_key(),
        vec![],
        std_caps(&fx.gid),
    );
    let mut u = m2.unsigned();
    u.seq = 3;
    u.signer_device_id = admin.id();
    u.signer_signing_pub = Some(attacker.sk.public_key().to_b64url());
    u.admin_grant = Some(grant);
    u.members.retain(|m| m.device_id != admin.id());
    u.members.push(forged_member);
    let forged = sign_group_manifest(u, &attacker.sk).unwrap();
    assert!(matches!(
        verify_group_manifest(&forged, NOW, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(book.ingest_group_manifest(&forged, NOW, None).is_err());
    assert_eq!(book.manifest(&fx.gid).unwrap().seq, 2);
}

#[test]
fn a2_seq_bounds_and_jump_limit() {
    let fx = fixture();
    let max = (1u64 << 53) - 1;
    let mut u = unsigned_of(&fx.manifest);
    u.seq = max + 1;
    assert!(sign_group_manifest(u.clone(), &fx.root.sk).is_err());
    u.seq = 0;
    assert!(sign_group_manifest(u.clone(), &fx.root.sk).is_err());
    u.seq = max;
    let at_max = sign_group_manifest(u, &fx.root.sk).unwrap();
    verify_group_manifest(&at_max, NOW, None).unwrap();
    let mut over = at_max.clone();
    over.seq = max + 1;
    assert!(verify_group_manifest(&over, NOW, None).is_err());

    let key = [0x42; 32];
    assert!(encode_group_rendezvous_frame(&fx.gid, max + 1, &key).is_err());
    let ok = encode_group_rendezvous_frame(&fx.gid, max, &key).unwrap();
    assert_eq!(decode_group_rendezvous_frame(&ok[..]).unwrap().seq, max);
    let mut raw = ok.to_vec();
    raw[20..28].copy_from_slice(&(max + 1).to_be_bytes());
    assert!(decode_group_rendezvous_frame(&raw).is_err());
    raw[20..28].copy_from_slice(&0u64.to_be_bytes());
    assert!(decode_group_rendezvous_frame(&raw).is_err());

    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    let jump = |delta: u64| {
        let mut u = unsigned_of(&fx.manifest);
        u.seq = 1 + delta;
        resign_root(&fx, u)
    };
    assert!(book.ingest_group_manifest(&jump(1025), NOW, None).is_err());
    assert_eq!(book.manifest(&fx.gid).unwrap().seq, 1);
    book.ingest_group_manifest(&jump(1024), NOW, None).unwrap();
    assert_eq!(book.manifest(&fx.gid).unwrap().seq, 1025);
}

#[test]
fn a3_admin_authority_is_re_verified_live() {
    let (fx, admin, _grant, m2, s2) = co_admin_fixture();
    let short = issue_admin_grant(
        &fx.root.sk,
        &fx.root.id(),
        &fx.gid,
        &admin.id(),
        admin.sk.public_key(),
        0,
        params().with_validity_secs(86_400),
    )
    .unwrap();
    let m3 = co_signed(&m2, &admin, &short, |_| {});
    let s3 = s2.rebound(3);
    let mut book = GroupBook::new();
    ingest(&mut book, &m3).unwrap();
    let frame = s3.to_rendezvous_frame(&fx.gid).unwrap();
    let admin_cap = Capability::parse(&format!("group.admin:{}", fx.gid)).unwrap();
    let later = NOW + 2 * 86_400;

    assert!(book.is_group_admin(&fx.gid, &admin.id(), NOW, None));
    book.authorize_group(&fx.gid, &admin.id(), &admin_cap, NOW, None)
        .unwrap();

    // Grant window elapsed while the manifest is still valid.
    assert!(!book.is_group_admin(&fx.gid, &admin.id(), later, None));
    assert!(book.is_group_admin(&fx.gid, &fx.root.id(), later, None));
    assert!(matches!(
        book.authorize_group(&fx.gid, &admin.id(), &admin_cap, later, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(matches!(
        book.ingest_group_rendezvous(&admin.id(), &frame[..], later, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(book.secrets(&fx.gid).is_none());

    // Root CRL revoking the stored grant removes admin authority immediately.
    let by_device = crl_for(&fx, vec![admin.id()], vec![]);
    let by_nonce = crl_for(&fx, vec![], vec![short.nonce.clone()]);
    for crl in [&by_device, &by_nonce] {
        assert!(!book.is_group_admin(&fx.gid, &admin.id(), NOW, Some(crl)));
        assert!(matches!(
            book.ingest_group_rendezvous(&admin.id(), &frame[..], NOW, Some(crl)),
            Err(CoreError::GroupUnauthorized(_))
        ));
        assert!(
            book.authorize_group(&fx.gid, &admin.id(), &admin_cap, NOW, Some(crl))
                .is_err()
        );
    }
    book.ingest_group_rendezvous(&admin.id(), &frame[..], NOW, None)
        .unwrap();
}

#[test]
fn a3_expired_stored_manifest_fails_closed_for_keys_and_bootstrap() {
    let fx = fixture();
    let peer = Dev::new(3);
    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    let frame = s2.to_rendezvous_frame(&fx.gid).unwrap();
    let late = NOW + DEFAULT_MANIFEST_VALIDITY_SECS;
    assert!(matches!(
        book.ingest_group_rendezvous(&fx.root.id(), &frame[..], late, None),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(!book.is_group_admin(&fx.gid, &fx.root.id(), late, None));
    book.ingest_group_rendezvous(&fx.root.id(), &frame[..], NOW, None)
        .unwrap();
    book.pair_bootstrap(&fx.gid, &fx.root.id(), &peer.id(), NOW)
        .unwrap();
    assert!(matches!(
        book.pair_bootstrap(&fx.gid, &fx.root.id(), &peer.id(), late),
        Err(CoreError::GroupUnauthorized(_))
    ));
    assert!(matches!(
        book.ingest_group_manifest(&m2, late, None),
        Err(CoreError::InvalidGroupManifest(_))
    ));
}

#[test]
fn a4_removed_members_must_be_revoked() {
    let fx = fixture();
    let peer = Dev::new(3);
    let (m2, _s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    let mut u = unsigned_of(&m2);
    u.seq = 3;
    u.members.retain(|m| m.device_id != peer.id());
    let silent_drop = resign_root(&fx, u);
    assert!(book.ingest_group_manifest(&silent_drop, NOW, None).is_err());
    assert_eq!(book.manifest(&fx.gid).unwrap().seq, 2);

    let mut u = unsigned_of(&m2);
    u.seq = 3;
    u.members.retain(|m| m.device_id != peer.id());
    u.revoked_members.push(peer.id());
    let out = book
        .ingest_group_manifest(&resign_root(&fx, u), NOW, None)
        .unwrap();
    assert_eq!(out.removed, vec![peer.id()]);
    assert_eq!(out.newly_revoked, vec![peer.id()]);
}

#[test]
fn a4_founding_root_identity_is_pinned_at_first_ingest() {
    let fx = fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    let other = Dev::new(7);
    let mut u = unsigned_of(&fx.manifest);
    u.seq = 2;
    u.signer_device_id = other.id();
    u.members[0] = GroupMember::new(
        other.st.public_bytes(),
        "root",
        fx.root.sk.public_key(),
        vec![],
        std_caps(&fx.gid),
    );
    let swapped = resign_root(&fx, u);
    verify_group_manifest(&swapped, NOW, None).unwrap();
    assert!(book.ingest_group_manifest(&swapped, NOW, None).is_err());
    assert_eq!(book.manifest(&fx.gid).unwrap().seq, 1);

    let mut u = unsigned_of(&fx.manifest);
    u.seq = 2;
    u.members[0].endpoints = vec!["wss://relay-b.example/v2/relay".to_string()];
    u.members[0].caps = vec![format!("group.recv:{}", fx.gid)];
    book.ingest_group_manifest(&resign_root(&fx, u), NOW, None)
        .unwrap();
}

#[test]
fn a4_rendezvous_key_must_rotate_after_a_revocation() {
    let fx = fixture();
    let peer = Dev::new(3);
    let root = GroupSigner::root(&fx.root.sk);
    let (m2, s2) = add_member(
        &fx.manifest,
        &root,
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    let f2 = s2.to_rendezvous_frame(&fx.gid).unwrap();
    book.ingest_group_rendezvous(&fx.root.id(), &f2[..], NOW, None)
        .unwrap();

    let (m3, s3) = remove_member(&m2, &root, &peer.id(), &s2, params()).unwrap();
    ingest(&mut book, &m3).unwrap();
    let replay_old = encode_group_rendezvous_frame(&fx.gid, 3, s2.group_rendezvous_key()).unwrap();
    assert!(
        book.ingest_group_rendezvous(&fx.root.id(), &replay_old[..], NOW, None)
            .is_err()
    );
    assert_eq!(book.secrets(&fx.gid), Some(&s2));
    let f3 = s3.to_rendezvous_frame(&fx.gid).unwrap();
    book.ingest_group_rendezvous(&fx.root.id(), &f3[..], NOW, None)
        .unwrap();
    assert_eq!(book.secrets(&fx.gid), Some(&s3));

    // A non-revoking seq may keep the key.
    let (m4, s4) = renew_manifest(&m3, &root, &s3, params()).unwrap();
    ingest(&mut book, &m4).unwrap();
    let f4 = s4.to_rendezvous_frame(&fx.gid).unwrap();
    book.ingest_group_rendezvous(&fx.root.id(), &f4[..], NOW, None)
        .unwrap();
}

#[test]
fn a5_explicit_null_optionals_are_rejected() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let signed = co_signed(&m2, &admin, &grant, |_| {});
    let mut raw = serde_json::to_value(&signed).unwrap();
    assert!(serde_json::from_value::<GroupManifest>(raw.clone()).is_ok());
    for field in ["signer_signing_pub", "admin_grant"] {
        let mut v = raw.clone();
        v[field] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<GroupManifest>(v.clone()).is_err(),
            "{field}"
        );
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(GroupManifest::from_wire_bytes(&bytes).is_err(), "{field}");
    }
    raw = serde_json::to_value(&fx.manifest).unwrap();
    raw["admin_grant"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<GroupManifest>(raw.clone()).is_err());
    let mut unsigned = serde_json::to_value(unsigned_of(&signed)).unwrap();
    unsigned["signer_signing_pub"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<GroupManifestUnsigned>(unsigned).is_err());
}

#[test]
fn a6_legacy_unpadded_receive_accepts_only_v1_frame_types() {
    let manifest = encode_inner_frame(InnerFrameType::GroupManifest, b"{}").unwrap();
    let rendezvous = encode_inner_frame(
        InnerFrameType::GroupRendezvous,
        &[0u8; GROUP_RENDEZVOUS_FRAME_LEN],
    )
    .unwrap();
    for raw in [&manifest, &rendezvous] {
        for allow in [true, false] {
            assert!(
                matches!(
                    decode_v2_inner_frame(raw, allow),
                    Err(CoreError::UnknownInnerFrameType(0x0A | 0x0B))
                ),
                "allow={allow}"
            );
        }
    }
    let data = encode_inner_frame(InnerFrameType::Data, b"hi").unwrap();
    assert!(decode_v2_inner_frame(&data, true).is_ok());
    assert!(decode_v2_inner_frame(&data, false).is_err());
    assert!(
        decode_v2_inner_frame(
            &pad_inner_frame(
                InnerFrameType::GroupRendezvous,
                &[0u8; GROUP_RENDEZVOUS_FRAME_LEN],
                &PaddingPolicy::v2_default()
            )
            .unwrap(),
            false
        )
        .is_ok()
    );
}

#[test]
fn a7_member_cap_resources_reject_escape_characters() {
    let fx = fixture();
    for resource in ["notes/a%2e%2e/b", "notes\\evil", "%2e%2e", "a\\b"] {
        for verb in ["sync.push", "group.send"] {
            let mut u = unsigned_of(&fx.manifest);
            u.members[0].caps = vec![format!("{verb}:{}/{resource}", fx.gid)];
            let err = verify_group_manifest(&resign_root(&fx, u), NOW, None).unwrap_err();
            assert!(
                matches!(err, CoreError::InvalidGroupCapabilityScope(_)),
                "{resource} {err:?}"
            );
        }
    }
    let mut u = unsigned_of(&fx.manifest);
    u.members[0].caps = vec![format!("sync.push:{}/notes/a", fx.gid)];
    verify_group_manifest(&resign_root(&fx, u), NOW, None).unwrap();

    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    let bad = Capability::parse(&format!("group.send:{}/a%2e", fx.gid)).unwrap();
    assert!(matches!(
        book.authorize_group(&fx.gid, &fx.root.id(), &bad, NOW, None),
        Err(CoreError::InvalidGroupCapabilityScope(_))
    ));
}

#[test]
fn a8_rendezvous_key_never_appears_in_debug_output() {
    let key = [0xAB; 32];
    let frame = encode_group_rendezvous_frame("grp_0123456789abcdef", 5, &key).unwrap();
    let decoded = decode_group_rendezvous_frame(&frame[..]).unwrap();
    let secrets = V2GroupSecrets::new(key, 5);
    let inner = V2InnerFrame::Frame {
        kind: InnerFrameType::GroupRendezvous,
        payload: zeroize::Zeroizing::new(frame.to_vec()),
    };
    let hexed = hex::encode(key);
    for dbg in [
        format!("{decoded:?}"),
        format!("{secrets:?}"),
        format!("{inner:?}"),
        format!(
            "{:?}",
            SessionAction::GroupRendezvousReceived(decoded.clone())
        ),
        format!(
            "{:?}",
            V2SessionAction::GroupRendezvousReceived(decoded.clone())
        ),
    ] {
        assert!(dbg.contains("redacted"), "{dbg}");
        assert!(!dbg.contains("171"), "{dbg}");
        assert!(!dbg.contains(&hexed), "{dbg}");
        assert!(!dbg.contains(&b64url_encode(&key)), "{dbg}");
    }

    let fx = fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    book.install_secrets(&fx.gid, fx.secrets.clone()).unwrap();
    let dbg = format!("{book:?}");
    assert!(!dbg.contains(&b64url_encode(fx.secrets.group_rendezvous_key())));
}

#[test]
fn a10_co_admin_cannot_rewrite_the_founding_root_entry() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();

    type RootEdit = Box<dyn Fn(&mut GroupManifestUnsigned)>;
    let edits: Vec<(&str, RootEdit)> = vec![
        (
            "endpoints",
            Box::new(|u| u.members[0].endpoints = vec!["wss://evil.example/v2/relay".to_string()]),
        ),
        ("caps", Box::new(|u| u.members[0].caps = Vec::new())),
        (
            "name",
            Box::new(|u| u.members[0].name = "renamed".to_string()),
        ),
    ];
    for (label, edit) in edits {
        let forged = co_signed(&m2, &admin, &grant, |u| edit(u));
        verify_group_manifest(&forged, NOW, None).unwrap();
        assert!(
            matches!(
                book.ingest_group_manifest(&forged, NOW, None),
                Err(CoreError::GroupUnauthorized(_))
            ),
            "{label}"
        );
        assert_eq!(book.manifest(&fx.gid).unwrap().seq, 2, "{label}");
    }

    // A co-admin that leaves the root entry untouched can still add members.
    let peer = Dev::new(3);
    let ok = co_signed(&m2, &admin, &grant, |u| {
        u.members.push(peer.member("peer", std_caps(&fx.gid)));
    });
    book.ingest_group_manifest(&ok, NOW, None).unwrap();

    // The root itself may change its own mutable fields.
    let mut u = unsigned_of(&ok);
    u.seq = 4;
    u.signer_device_id = fx.root.id();
    u.signer_signing_pub = None;
    u.admin_grant = None;
    u.members[0].endpoints = vec!["wss://relay-b.example/v2/relay".to_string()];
    book.ingest_group_manifest(&resign_root(&fx, u), NOW, None)
        .unwrap();
}

#[test]
fn k1_install_secrets_requires_rotation_after_revocation() {
    let fx = fixture();
    let peer = Dev::new(3);
    let (m2, s2) = add_member(
        &fx.manifest,
        &GroupSigner::root(&fx.root.sk),
        peer.member("peer", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let (m3, s3) = remove_member(
        &m2,
        &GroupSigner::root(&fx.root.sk),
        &peer.id(),
        &s2,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    book.install_secrets(&fx.gid, s2.clone()).unwrap();
    ingest(&mut book, &m3).unwrap();

    assert!(book.install_secrets(&fx.gid, s2.clone()).is_err());
    assert!(book.install_secrets(&fx.gid, s2.rebound(3)).is_err());
    assert_eq!(book.secrets(&fx.gid), Some(&s2));
    book.install_secrets(&fx.gid, s3.clone()).unwrap();
    assert_eq!(book.secrets(&fx.gid), Some(&s3));
    book.install_secrets(&fx.gid, s3.clone()).unwrap();
}

#[test]
fn k2_admin_status_answers_only_the_exact_admin_capability() {
    let fx = fixture();
    let mut book = GroupBook::new();
    ingest(&mut book, &fx.manifest).unwrap();
    let cap = |s: &str| Capability::parse(s).unwrap();
    let gid = &fx.gid;
    book.authorize_group(
        gid,
        &fx.root.id(),
        &cap(&format!("group.admin:{gid}")),
        NOW,
        None,
    )
    .unwrap();
    for suffix in ["/anything", "/*", "/abcd"] {
        assert!(matches!(
            book.authorize_group(
                gid,
                &fx.root.id(),
                &cap(&format!("group.admin:{gid}{suffix}")),
                NOW,
                None
            ),
            Err(CoreError::GroupUnauthorized(_))
        ));
    }
}

#[test]
fn k4_bare_group_frames_are_rejected_under_every_v2_policy() {
    let bare = encode_inner_frame(InnerFrameType::GroupManifest, b"{}").unwrap();
    for allow in [false, true] {
        assert!(matches!(
            decode_v2_inner_frame(&bare, allow),
            Err(CoreError::UnknownInnerFrameType(0x0A))
        ));
    }
    let bare_rv = encode_inner_frame(InnerFrameType::GroupRendezvous, &[0; 60]).unwrap();
    assert!(matches!(
        decode_v2_inner_frame(&bare_rv, true),
        Err(CoreError::UnknownInnerFrameType(0x0B))
    ));
}

#[test]
fn k5_group_secrets_serde_roundtrip_and_strictness() {
    let secrets = V2GroupSecrets::new([9; 32], 4);
    let json = serde_json::to_string(&secrets).unwrap();
    assert_eq!(
        serde_json::from_str::<V2GroupSecrets>(&json).unwrap(),
        secrets
    );
    let bad = json.replace("\"seq\"", "\"x\":1,\"seq\"");
    assert!(serde_json::from_str::<V2GroupSecrets>(&bad).is_err());
}

fn hash_pinned_roster(host: &EndpointIdentity, hash: [u8; 32]) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            None,
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    roster.pin_signing_hash(host.host_id(), hash).unwrap();
    roster
}

#[test]
fn v1_initiator_resolves_a_hash_pinned_signing_key_from_host_hello() {
    let (host, cli, mut host_roster, _) = v1_pair();
    let good = host.signing_key().public_key().sha256_hash();

    let mut cli_roster = hash_pinned_roster(&host, good);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    let m3 = v1_bytes(init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, NOW, 3, &mut host_roster).unwrap();
    assert!(init.is_established());
    assert_eq!(
        cli_roster.get(host.host_id()).unwrap().signing_pub.as_ref(),
        Some(host.signing_key().public_key())
    );

    let mut bad_roster = hash_pinned_roster(&host, [0xAA; 32]);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    assert_eq!(
        init.feed_bytes(&m2, NOW, 2, &mut bad_roster).unwrap_err(),
        CoreError::HostKeyUnverified
    );
    assert!(
        bad_roster
            .get(host.host_id())
            .unwrap()
            .signing_pub
            .is_none()
    );

    let mut no_pin = Roster::new();
    no_pin
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            None,
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    assert!(matches!(
        init.feed_bytes(&m2, NOW, 2, &mut no_pin),
        Err(CoreError::IncompletePin(_))
    ));
}

#[test]
fn roster_signing_hash_pins_are_transient_and_conflict_checked() {
    let host = Dev::new(7);
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "peer".into(),
            "Peer".into(),
            *host.st.public_bytes(),
            Some(host.sk.public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    assert_eq!(
        roster.pin_signing_hash("peer", [1; 32]),
        Err(CoreError::HostKeyUnverified)
    );
    roster
        .pin_signing_hash("peer", host.sk.public_key().sha256_hash())
        .unwrap();
    assert!(matches!(
        roster.pin_signing_hash("ghost", [1; 32]),
        Err(CoreError::PeerNotFound(_))
    ));
    let json = serde_json::to_string(&roster).unwrap();
    assert!(!json.contains("signing_hash_pins"));
}

#[test]
fn pairwise_secrets_are_group_scoped_and_dropped_on_revocation() {
    let fx = fixture();
    let signer = GroupSigner::root(&fx.root.sk);
    let b = Dev::new(2);
    let c = Dev::new(3);
    let (m2, s2) = add_member(
        &fx.manifest,
        &signer,
        b.member("b", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let (m3, s3) = add_member(
        &m2,
        &signer,
        c.member("c", std_caps(&fx.gid)),
        &s2,
        params(),
    )
    .unwrap();
    let pw = V2PeerSecrets::new([0x11; 32], [0x22; 32]);

    let mut pushed = GroupBook::new();
    ingest(&mut pushed, &m3).unwrap();
    assert!(matches!(
        pushed.set_pairwise_secrets(&fx.gid, &Dev::new(9).id(), pw.clone()),
        Err(CoreError::GroupMemberRevoked(_))
    ));
    assert!(matches!(
        pushed.set_pairwise_secrets("grp_unknown", &b.id(), pw.clone()),
        Err(CoreError::GroupNotFound(_))
    ));
    pushed
        .set_pairwise_secrets(&fx.gid, &b.id(), pw.clone())
        .unwrap();
    pushed
        .set_pairwise_secrets(&fx.gid, &c.id(), pw.clone())
        .unwrap();
    let json = serde_json::to_string(&pushed).unwrap();
    let reloaded: GroupBook = serde_json::from_str(&json).unwrap();
    assert_eq!(reloaded.pairwise_secrets(&fx.gid, &b.id()), Some(&pw));

    let mut gossiped = reloaded.clone();
    let (m4, _) = remove_member(&m3, &signer, &b.id(), &s3, params()).unwrap();
    ingest(&mut pushed, &m4).unwrap();
    gossiped.ingest_gossiped_manifest(&m4, NOW, None).unwrap();
    for book in [&pushed, &gossiped] {
        assert!(book.pairwise_secrets(&fx.gid, &b.id()).is_none());
        assert_eq!(book.pairwise_secrets(&fx.gid, &c.id()), Some(&pw));
    }
    assert!(pushed.remove_pairwise_secrets(&fx.gid, &c.id()));
    assert!(!pushed.remove_pairwise_secrets(&fx.gid, &c.id()));

    let mut tampered: serde_json::Value = serde_json::from_str(&json).unwrap();
    let record = &mut tampered["groups"][&fx.gid];
    record["manifest"] = serde_json::to_value(&m4).unwrap();
    let pruned: GroupBook = serde_json::from_value(tampered).unwrap();
    assert!(pruned.pairwise_secrets(&fx.gid, &b.id()).is_none());
    assert!(pruned.pairwise_secrets(&fx.gid, &c.id()).is_some());

    gossiped.forget_group(&fx.gid);
    assert!(gossiped.pairwise_secrets(&fx.gid, &c.id()).is_none());
}

#[test]
fn authorize_group_denies_a_sender_listed_in_the_root_crl() {
    let fx = fixture();
    let signer = GroupSigner::root(&fx.root.sk);
    let b = Dev::new(2);
    let (m2, _) = add_member(
        &fx.manifest,
        &signer,
        b.member("b", std_caps(&fx.gid)),
        &fx.secrets,
        params(),
    )
    .unwrap();
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    let cap = Capability::parse(&format!("group.send:{}", fx.gid)).unwrap();
    book.authorize_group(&fx.gid, &b.id(), &cap, NOW, None)
        .unwrap();
    let crl = resolved_at(&fx, &fx.root.id(), crl_for(&fx, vec![b.id()], vec![])).unwrap();
    assert!(matches!(
        book.authorize_group(&fx.gid, &b.id(), &cap, NOW, Some(&crl)),
        Err(CoreError::GroupMemberRevoked(_))
    ));
    book.authorize_group(&fx.gid, &fx.root.id(), &cap, NOW, Some(&crl))
        .unwrap();
}

fn v2_host_and_client() -> (EndpointIdentity, EndpointIdentity) {
    (
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x41; 32]),
            SigningKeypair::from_seed([0x42; 32]),
        ),
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x51; 32]),
            SigningKeypair::from_seed([0x52; 32]),
        ),
    )
}

fn v2_try(
    host: &EndpointIdentity,
    cli: &EndpointIdentity,
    host_roster: &mut Roster,
    secret: [u8; 32],
    now_ms: u64,
) -> Result<V2SessionResponder, CoreError> {
    let mut cli_roster = hash_pinned_roster(host, host.signing_key().public_key().sha256_hash());
    cli_roster
        .upgrade_peer_to_v2(host.host_id(), V2PeerSecrets::new(secret, [0; 32]))
        .unwrap();
    let mut init = V2SessionInitiator::new(cli, host.host_id(), secret, None, None).unwrap();
    let mut resp = V2SessionResponder::new(host).unwrap();
    let m1 = v2_bytes(init.start(NOW).unwrap());
    let m2 = v2_bytes(resp.feed_bytes(&m1, NOW, now_ms, host_roster)?);
    let m3 = v2_bytes(init.feed_bytes(&m2, NOW, now_ms + 1, &mut cli_roster)?);
    resp.feed_bytes(&m3, NOW, now_ms + 2, host_roster)?;
    assert!(resp.is_established());
    Ok(resp)
}

#[test]
fn v2_responder_accepts_registered_alternates_and_reports_the_match() {
    let (host, cli) = v2_host_and_client();
    let primary = [0x66; 32];
    let alternate = [0x67; 32];
    let mut host_roster = Roster::new();
    host_roster
        .insert_pinned_host(
            cli.device_id(),
            "cli".into(),
            *cli.static_key().public_bytes(),
            None,
            0,
            vec![],
        )
        .unwrap();
    host_roster
        .upgrade_peer_to_v2(&cli.device_id(), V2PeerSecrets::new(primary, [0; 32]))
        .unwrap();
    assert!(v2_try(&host, &cli, &mut host_roster, alternate, 10).is_err());
    assert!(matches!(
        host_roster.add_rendezvous_alternate("ghost", V2PeerSecrets::new(alternate, [0; 32])),
        Err(CoreError::PeerNotFound(_))
    ));
    host_roster
        .add_rendezvous_alternate(&cli.device_id(), V2PeerSecrets::new(alternate, [0; 32]))
        .unwrap();
    let resp = v2_try(&host, &cli, &mut host_roster, alternate, 20).unwrap();
    assert_eq!(resp.matched_rendezvous_secret(), Some(&alternate));
    let resp = v2_try(&host, &cli, &mut host_roster, primary, 30).unwrap();
    assert_eq!(resp.matched_rendezvous_secret(), Some(&primary));
    assert!(v2_try(&host, &cli, &mut host_roster, [0x68; 32], 40).is_err());
    let json = serde_json::to_string(&host_roster).unwrap();
    assert!(!json.contains("rendezvous_alternates"));
}

fn followed_template(host: &EndpointIdentity, static_pub: [u8; 32]) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            static_pub,
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    roster
}

#[test]
fn manifest_pinned_initiators_never_follow_a_rotation_chain() {
    let (host, cli, mut host_roster, _) = v1_pair();
    let old_static = *host.static_key().public_bytes();
    let old_hash = host.signing_key().public_key().sha256_hash();
    let mut rotated = host.clone();
    rotated
        .rotate(
            StaticKeypair::from_scalar([0x43; 32]),
            SigningKeypair::from_seed([0x44; 32]),
            NOW - 10,
        )
        .unwrap();

    let mut followed = followed_template(&host, old_static);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&rotated, None).unwrap();
    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    init.feed_bytes(&m2, NOW, 2, &mut followed).unwrap();
    assert!(
        init.is_established(),
        "ordinary pins follow signed rotation"
    );

    let mut pinned = followed_template(&host, old_static);
    pinned.pin_signing_hash(host.host_id(), old_hash).unwrap();
    assert!(pinned.is_manifest_pinned(host.host_id()));
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&rotated, None).unwrap();
    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    assert_eq!(
        init.feed_bytes(&m2, NOW, 2, &mut pinned).unwrap_err(),
        CoreError::HostKeyUnverified
    );
    assert!(!init.is_established());
    assert_eq!(pinned.get(host.host_id()).unwrap().static_pub, old_static);
}

// H8: first-contact and capacity policy shared by the runtime and the browser.

fn pin_dev(roster: &mut Roster, dev: &Dev) {
    roster
        .insert_pinned_host(
            dev.id(),
            "peer".to_owned(),
            *dev.st.public_bytes(),
            Some(dev.sk.public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
}

/// A root-signed group (root seed `root_seed`) that lists `local` as an active member.
fn group_with_local(
    root_seed: u8,
    local: &Dev,
) -> (Dev, GroupManifest, V2GroupSecrets, GroupManifest) {
    let root = Dev::new(root_seed);
    let gid = group_id_from_root(root.sk.public_key());
    let (m1, s1) = tendril_core::group::create_group(
        &root.sk,
        "g",
        2,
        root.member("root", std_caps(&gid)),
        params(),
    )
    .unwrap();
    let (m2, s2) = add_member(
        &m1,
        &GroupSigner::root(&root.sk),
        local.member("local", std_caps(&gid)),
        &s1,
        params(),
    )
    .unwrap();
    (root, m2, s2, m1)
}

fn unauthorized_msg(err: &CoreError) -> &str {
    match err {
        CoreError::GroupUnauthorized(m) => m,
        other => panic!("expected GroupUnauthorized, got {other:?}"),
    }
}

#[test]
fn first_contact_accepts_active_signer_and_member_local() {
    let local = Dev::new(3);
    let (root, m2, _, _) = group_with_local(100, &local);
    let mut roster = Roster::new();
    pin_dev(&mut roster, &root);
    check_first_contact(&roster, &local.id(), &root.id(), &m2).unwrap();
}

#[test]
fn first_contact_refuses_each_unmet_condition() {
    let local = Dev::new(3);
    let (root, m2, _, _) = group_with_local(100, &local);
    let mut roster = Roster::new();
    pin_dev(&mut roster, &root);

    let other = Dev::new(4);
    let err = check_first_contact(&roster, &local.id(), &other.id(), &m2).unwrap_err();
    assert!(unauthorized_msg(&err).contains("manifest signer"), "{err}");

    let err = check_first_contact(&Roster::new(), &local.id(), &root.id(), &m2).unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("active paired peer"),
        "{err}"
    );

    let mut wrong_pin = Roster::new();
    wrong_pin
        .insert_pinned_host(
            root.id(),
            "peer".to_owned(),
            *root.st.public_bytes(),
            Some(Dev::new(9).sk.public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    let err = check_first_contact(&wrong_pin, &local.id(), &root.id(), &m2).unwrap_err();
    assert!(unauthorized_msg(&err).contains("pinned key"), "{err}");

    let outsider = Dev::new(5);
    let err = check_first_contact(&roster, &outsider.id(), &root.id(), &m2).unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("not an active member"),
        "{err}"
    );
}

#[test]
fn first_contact_resolves_peer_by_derived_device_id_not_roster_key() {
    let local = Dev::new(3);
    let (root, m2, _, _) = group_with_local(100, &local);
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "host-chosen-label".to_owned(),
            "peer".to_owned(),
            *root.st.public_bytes(),
            Some(root.sk.public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    let handles = check_first_contact(&roster, &local.id(), &root.id(), &m2).unwrap();
    assert_eq!(
        handles,
        BTreeSet::from(["host-chosen-label".to_owned(), root.id()])
    );

    // Siblings sharing the static key or the signing identity add their handles; others do not.
    roster
        .record_pending_pair(
            *root.st.public_bytes(),
            Some(root.sk.public_key().clone()),
            "peer".to_owned(),
            "peer".to_owned(),
            "1111".to_owned(),
        )
        .unwrap();
    roster.confirm_peer(&root.id(), Some("1111")).unwrap();
    let other_static = Dev::new(48);
    pin_as(
        &mut roster,
        "same-signing",
        other_static.st.public_bytes(),
        &root.sk,
    );
    let unrelated = Dev::new(49);
    pin_dev(&mut roster, &unrelated);
    let handles = check_first_contact(&roster, &local.id(), &root.id(), &m2).unwrap();
    assert_eq!(
        handles,
        BTreeSet::from([
            "host-chosen-label".to_owned(),
            root.id(),
            "same-signing".to_owned(),
            other_static.id(),
        ])
    );
}

#[test]
fn first_contact_refuses_crl_revoked_signer() {
    let local = Dev::new(3);
    let (root, m2, _, _) = group_with_local(100, &local);
    let mut roster = Roster::new();
    pin_dev(&mut roster, &root);
    let admin = Dev::new(6);
    pin_dev(&mut roster, &admin);
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: admin.id(),
            seq: 1,
            revoked_devices: vec![root.id()],
            revoked_nonces: Vec::new(),
            ts: "2026-11-25T00:00:00Z".to_owned(),
        },
        &admin.sk,
    )
    .unwrap();
    roster
        .ingest_crl(crl, &admin.id(), admin.sk.public_key())
        .unwrap();
    let err = check_first_contact(&roster, &local.id(), &root.id(), &m2).unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("active paired peer"),
        "{err}"
    );
}

/// Pins `dev` under `label` with `signing` and records its reverse pairing as a `dev_` entry,
/// confirmed when `confirm` is set, so the roster holds two entries sharing one static key.
fn reverse_paired(dev: &Dev, label: &str, signing: bool, confirm: bool) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            label.to_owned(),
            "peer".to_owned(),
            *dev.st.public_bytes(),
            signing.then(|| dev.sk.public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    roster
        .record_pending_pair(
            *dev.st.public_bytes(),
            Some(dev.sk.public_key().clone()),
            "peer".to_owned(),
            "peer".to_owned(),
            "1111".to_owned(),
        )
        .unwrap();
    if confirm {
        roster.confirm_peer(&dev.id(), Some("1111")).unwrap();
    }
    roster
}

#[test]
fn first_contact_selects_the_usable_entry_of_a_reverse_paired_signer() {
    let local = Dev::new(3);
    let (root, m2, _, _) = group_with_local(100, &local);
    for label in ["a-host", "z-host"] {
        let keyless_alias = reverse_paired(&root, label, false, true);
        check_first_contact(&keyless_alias, &local.id(), &root.id(), &m2)
            .unwrap_or_else(|e| panic!("keyless {label}: {e}"));
        let pending_dev = reverse_paired(&root, label, true, false);
        check_first_contact(&pending_dev, &local.id(), &root.id(), &m2)
            .unwrap_or_else(|e| panic!("pending dev_ with {label}: {e}"));
    }
}

#[test]
fn first_contact_refuses_when_any_alias_of_the_signer_is_revoked() {
    let local = Dev::new(3);
    let (root, m2, _, _) = group_with_local(100, &local);
    let admin = Dev::new(6);
    for label in ["a-host", "z-host"] {
        let mut roster = reverse_paired(&root, label, true, true);
        pin_dev(&mut roster, &admin);
        check_first_contact(&roster, &local.id(), &root.id(), &m2).unwrap();
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: admin.id(),
                seq: 1,
                revoked_devices: vec![label.to_owned()],
                revoked_nonces: Vec::new(),
                ts: "2026-11-25T00:00:00Z".to_owned(),
            },
            &admin.sk,
        )
        .unwrap();
        roster
            .ingest_crl(crl, &admin.id(), admin.sk.public_key())
            .unwrap();
        let err = check_first_contact(&roster, &local.id(), &root.id(), &m2).unwrap_err();
        assert!(
            unauthorized_msg(&err).contains("active paired peer"),
            "{label}: {err}"
        );
    }
}

#[test]
fn capacity_caps_local_groups_but_always_allows_updates() {
    let local = Dev::new(3);
    let mut book = GroupBook::new();
    let mut first = None;
    for i in 0..MAX_LOCAL_GROUPS {
        let (root, m2, _, _) = group_with_local(100 + u8::try_from(i).unwrap(), &local);
        check_group_capacity(&book, &local.id(), &m2.group_id).unwrap();
        ingest(&mut book, &m2).unwrap();
        first.get_or_insert((root, m2));
    }
    let (_, extra, _, _) = group_with_local(200, &local);
    let err = check_group_capacity(&book, &local.id(), &extra.group_id).unwrap_err();
    assert!(unauthorized_msg(&err).contains("local groups"), "{err}");
    let (_, stored) = first.unwrap();
    check_group_capacity(&book, &local.id(), &stored.group_id).unwrap();
}

#[test]
fn capacity_counts_the_root_and_frees_slots_for_left_groups() {
    let local = Dev::new(3);
    let mut book = GroupBook::new();
    let mut left = None;
    for i in 0..MAX_LOCAL_GROUPS {
        let (root, m2, s2, _) = group_with_local(100 + u8::try_from(i).unwrap(), &local);
        ingest(&mut book, &m2).unwrap();
        if i == 0 {
            left = Some((root, m2, s2));
        }
    }
    let (_, extra, _, _) = group_with_local(200, &local);
    assert!(check_group_capacity(&book, &local.id(), &extra.group_id).is_err());

    let (root, m2, s2) = left.unwrap();
    let (removed, _) = remove_member(
        &m2,
        &GroupSigner::root(&root.sk),
        &local.id(),
        &s2,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap();
    book.ingest_group_manifest(&removed, NOW + 10, None)
        .unwrap();
    check_group_capacity(&book, &local.id(), &extra.group_id).unwrap();

    // The root of a stored group holds a slot even though it is a member of it.
    assert!(book.holds_group(&root.id(), &removed.group_id));
    assert_eq!(
        book.root_device_id(&removed.group_id).as_deref(),
        Some(root.id().as_str())
    );
    assert_eq!(
        root_device_in(&removed, root.sk.public_key()).as_deref(),
        Some(root.id().as_str())
    );
}

#[test]
fn capacity_caps_stored_groups_including_left_ones() {
    let local = Dev::new(3);
    let mut book = GroupBook::new();
    for i in 0..MAX_STORED_GROUPS {
        let (root, m2, s2, _) = group_with_local(100 + u8::try_from(i).unwrap(), &local);
        ingest(&mut book, &m2).unwrap();
        let (removed, _) = remove_member(
            &m2,
            &GroupSigner::root(&root.sk),
            &local.id(),
            &s2,
            GroupBuildParams::new(NOW + 10),
        )
        .unwrap();
        book.ingest_group_manifest(&removed, NOW + 10, None)
            .unwrap();
    }
    assert_eq!(book.group_ids().len(), MAX_STORED_GROUPS);
    let (_, extra, _, _) = group_with_local(200, &local);
    let err = check_group_capacity(&book, &local.id(), &extra.group_id).unwrap_err();
    assert!(unauthorized_msg(&err).contains("stored groups"), "{err}");

    let known = book.group_ids().remove(0);
    check_group_capacity(&book, &local.id(), &known).unwrap();
    assert!(book.forget_group(&known));
    check_group_capacity(&book, &local.id(), &extra.group_id).unwrap();
}

#[test]
fn drop_secrets_if_left_keeps_manifest_and_spares_members_and_root() {
    let local = Dev::new(3);
    let (root, m2, s2, _) = group_with_local(100, &local);
    let mut book = GroupBook::new();
    ingest(&mut book, &m2).unwrap();
    book.install_secrets(&m2.group_id, s2.clone()).unwrap();

    assert!(!drop_secrets_if_left(&mut book, &local.id(), &m2.group_id));
    assert!(!drop_secrets_if_left(&mut book, &root.id(), &m2.group_id));
    assert!(!drop_secrets_if_left(&mut book, &local.id(), "grp_missing"));
    assert!(book.secrets(&m2.group_id).is_some());

    let (removed, _) = remove_member(
        &m2,
        &GroupSigner::root(&root.sk),
        &local.id(),
        &s2,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap();
    book.ingest_group_manifest(&removed, NOW + 10, None)
        .unwrap();
    assert!(drop_secrets_if_left(&mut book, &local.id(), &m2.group_id));
    assert!(book.secrets(&m2.group_id).is_none());
    assert!(book.manifest(&m2.group_id).is_some());
    assert!(!drop_secrets_if_left(&mut book, &root.id(), &m2.group_id));
}

#[test]
fn rendezvous_membership_check_refuses_left_devices_only() {
    let local = Dev::new(3);
    let (root, m2, s2, _) = group_with_local(100, &local);
    let mut book = GroupBook::new();
    check_rendezvous_local_membership(&book, &local.id(), &m2.group_id).unwrap();
    ingest(&mut book, &m2).unwrap();
    check_rendezvous_local_membership(&book, &local.id(), &m2.group_id).unwrap();
    check_rendezvous_local_membership(&book, &root.id(), &m2.group_id).unwrap();

    let (removed, _) = remove_member(
        &m2,
        &GroupSigner::root(&root.sk),
        &local.id(),
        &s2,
        GroupBuildParams::new(NOW + 10),
    )
    .unwrap();
    book.ingest_group_manifest(&removed, NOW + 10, None)
        .unwrap();
    let err = check_rendezvous_local_membership(&book, &local.id(), &m2.group_id).unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("not an active member"),
        "{err}"
    );
    check_rendezvous_local_membership(&book, &root.id(), &m2.group_id).unwrap();
}

// Root CRL authority: every stored list signed by the pinned founding root key applies.

fn root_list(
    issuer: &str,
    seq: u64,
    devices: Vec<String>,
    nonces: Vec<String>,
    key: &SigningKeypair,
) -> RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: issuer.to_owned(),
            seq,
            revoked_devices: devices,
            revoked_nonces: nonces,
            ts: "2026-11-25T00:00:00Z".to_owned(),
        },
        key,
    )
    .unwrap()
}

fn pin_as(roster: &mut Roster, label: &str, static_pub: &[u8; 32], key: &SigningKeypair) {
    roster
        .insert_pinned_host(
            label.to_owned(),
            "peer".to_owned(),
            *static_pub,
            Some(key.public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
}

fn store_list(roster: &mut Roster, list: RevocationList, key: &SigningKeypair) {
    let issuer = list.issuer.clone();
    roster.ingest_crl(list, &issuer, key.public_key()).unwrap();
}

/// A roster that pins the fixture root under `label` and stores `list` there.
fn resolved_at(fx: &Fixture, label: &str, list: RevocationList) -> Option<RevocationList> {
    let mut roster = Roster::new();
    pin_as(&mut roster, label, fx.root.st.public_bytes(), &fx.root.sk);
    store_list(&mut roster, list, &fx.root.sk);
    root_crl(&roster, &fx.root.id(), fx.root.sk.public_key(), None).unwrap()
}

#[test]
fn root_crl_authority_is_the_pinned_root_key() {
    let fx = fixture();
    let root_pub = fx.root.sk.public_key();
    let x = Dev::new(40);
    let y = Dev::new(41);
    let mut roster = Roster::new();
    pin_as(
        &mut roster,
        "root-host",
        fx.root.st.public_bytes(),
        &fx.root.sk,
    );
    let list = root_list("root-host", 1, vec![x.id()], vec![], &fx.root.sk);
    store_list(&mut roster, list.clone(), &fx.root.sk);
    assert_eq!(
        root_crl(&roster, &fx.root.id(), root_pub, None).unwrap(),
        Some(list.clone())
    );

    // A foreign host keyed with the root device id, never rotated, with its own list.
    let foreign = Dev::new(42);
    pin_as(
        &mut roster,
        &fx.root.id(),
        foreign.st.public_bytes(),
        &foreign.sk,
    );
    let foreign_list = root_list(&fx.root.id(), 7, vec![y.id()], vec![], &foreign.sk);
    store_list(&mut roster, foreign_list, &foreign.sk);
    assert_eq!(
        root_crl(&roster, &fx.root.id(), root_pub, None).unwrap(),
        Some(list)
    );

    // A root-signed list stored under an unrelated entry label still counts.
    let other = Dev::new(43);
    pin_as(
        &mut roster,
        "other-label",
        other.st.public_bytes(),
        &other.sk,
    );
    store_list(
        &mut roster,
        root_list("other-label", 1, vec![y.id()], vec![], &fx.root.sk),
        &fx.root.sk,
    );
    let merged = root_crl(&roster, &fx.root.id(), root_pub, None)
        .unwrap()
        .unwrap();
    let mut revoked = merged.revoked_devices;
    revoked.sort();
    let mut expected = vec![x.id(), y.id()];
    expected.sort();
    assert_eq!(revoked, expected);
}

#[test]
fn root_crl_unions_label_streams() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let root_pub = fx.root.sk.public_key();
    let x = Dev::new(44);
    let other = Dev::new(45);
    let co = co_signed(&m2, &admin, &grant, |_| {});
    let send = Capability::parse(&format!("group.send:{}", fx.gid)).unwrap();
    for (seq_a, seq_b) in [(9, 1), (1, 1)] {
        let mut roster = Roster::new();
        pin_as(&mut roster, "a", fx.root.st.public_bytes(), &fx.root.sk);
        pin_as(&mut roster, "b", other.st.public_bytes(), &other.sk);
        store_list(
            &mut roster,
            root_list("a", seq_a, vec![x.id()], vec![], &fx.root.sk),
            &fx.root.sk,
        );
        store_list(
            &mut roster,
            root_list(
                "b",
                seq_b,
                vec![admin.id()],
                vec![grant.nonce.clone()],
                &fx.root.sk,
            ),
            &fx.root.sk,
        );
        let merged = root_crl(&roster, &fx.root.id(), root_pub, None)
            .unwrap()
            .unwrap();
        assert_eq!(merged.revoked_devices, vec![x.id(), admin.id()]);
        assert_eq!(merged.revoked_nonces, vec![grant.nonce.clone()]);
        assert_eq!(merged.seq, seq_a.max(seq_b));
        assert_eq!(merged.issuer, fx.root.id());

        let mut book = GroupBook::new();
        ingest(&mut book, &m2).unwrap();
        assert!(matches!(
            book.authorize_group(&fx.gid, &x.id(), &send, NOW, Some(&merged)),
            Err(CoreError::GroupMemberRevoked(_))
        ));
        assert!(matches!(
            book.ingest_group_manifest(&co, NOW, Some(&merged)),
            Err(CoreError::GroupUnauthorized(_))
        ));
    }
}

fn runtime_identity(seed: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([seed; 32]),
        SigningKeypair::from_seed([seed.wrapping_add(0x40); 32]),
    )
}

fn identity_member(identity: &EndpointIdentity, gid: &str) -> GroupMember {
    GroupMember::new(
        identity.static_key().public_bytes(),
        "root",
        identity.signing_key().public_key(),
        vec![],
        std_caps(gid),
    )
}

/// A group rooted at `root` with `c` as a member; returns the founding key and the manifest.
fn identity_group(root: &EndpointIdentity, c: &Dev) -> (HybridSigningPublicKey, GroupManifest) {
    let root_pub = root.signing_key().public_key().clone();
    let gid = group_id_from_root(&root_pub);
    let (m1, s1) = tendril_core::group::create_group(
        root.signing_key(),
        "g",
        2,
        identity_member(root, &gid),
        params(),
    )
    .unwrap();
    let (m2, _) = add_member(
        &m1,
        &GroupSigner::root(root.signing_key()),
        c.member("c", std_caps(&gid)),
        &s1,
        params(),
    )
    .unwrap();
    (root_pub, m2)
}

/// Rotates `root`, re-signs its own list, and applies both on `member` under `label`.
fn rotate_root(
    root: &mut EndpointIdentity,
    root_roster: &mut Roster,
    member: &mut Roster,
    label: &str,
) {
    root.rotate(
        StaticKeypair::from_scalar([0xE1; 32]),
        SigningKeypair::from_seed([0xE2; 32]),
        NOW,
    )
    .unwrap();
    let resigned = root_roster.resign_crl(root, NOW).unwrap().unwrap();
    member
        .apply_verified_rotation(
            label,
            root.rotation_chain(),
            root.static_key().public_bytes(),
            root.signing_key().public_key(),
        )
        .unwrap();
    member
        .ingest_crl(resigned, label, root.signing_key().public_key())
        .unwrap();
}

#[test]
fn root_crl_fails_closed_after_root_rotation() {
    let mut root = runtime_identity(0x31);
    let root_dev = root.device_id();
    assert_eq!(root.host_id(), root_dev);
    let c = Dev::new(46);
    let (root_pub, manifest) = identity_group(&root, &c);
    let gid = manifest.group_id.clone();
    let mut book = GroupBook::new();
    ingest(&mut book, &manifest).unwrap();
    let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

    let list = root_list(&root_dev, 1, vec![c.id()], vec![], root.signing_key());
    let mut root_roster = Roster::new();
    store_list(&mut root_roster, list.clone(), root.signing_key());
    let mut member = Roster::new();
    member
        .insert_pinned_host(
            root_dev.clone(),
            "root".to_owned(),
            *root.static_key().public_bytes(),
            Some(root_pub.clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    store_list(&mut member, list, root.signing_key());
    let crl = root_crl(&member, &root_dev, &root_pub, None).unwrap();
    assert!(matches!(
        book.authorize_group(&gid, &c.id(), &send, NOW, crl.as_ref()),
        Err(CoreError::GroupMemberRevoked(_))
    ));

    rotate_root(&mut root, &mut root_roster, &mut member, &root_dev);
    assert_eq!(member.get(&root_dev).unwrap().rotation_seq, 1);
    for roster in [&member, &root_roster] {
        let err = root_crl(roster, &root_dev, &root_pub, None).unwrap_err();
        assert!(unauthorized_msg(&err).contains("group root key"), "{err}");
    }
}

#[test]
fn co_admin_grant_honors_a_host_labeled_root_crl() {
    let (fx, admin, grant, m2, _s2) = co_admin_fixture();
    let co = co_signed(&m2, &admin, &grant, |_| {});
    let attempt = |list: RevocationList| {
        let crl = resolved_at(&fx, "root-host", list);
        assert!(crl.is_some());
        let mut book = GroupBook::new();
        ingest(&mut book, &m2).unwrap();
        book.ingest_group_manifest(&co, NOW, crl.as_ref())
            .map(|_| ())
    };
    attempt(root_list("root-host", 1, vec![], vec![], &fx.root.sk)).unwrap();
    for list in [
        root_list("root-host", 1, vec![admin.id()], vec![], &fx.root.sk),
        root_list(
            "root-host",
            1,
            vec![],
            vec![grant.nonce.clone()],
            &fx.root.sk,
        ),
    ] {
        assert!(matches!(
            attempt(list),
            Err(CoreError::GroupUnauthorized(_))
        ));
    }
}

/// Known limitation "Rotated host-labeled root" (`docs/design/groups.md`): a core-API root whose
/// roster label differs from its `device_id` stops supplying a root CRL once it rotates.
#[test]
fn host_labeled_root_rotation_behaviour() {
    let mut root = runtime_identity(0x32).with_host_id("root-host");
    let root_dev = root.device_id();
    let c = Dev::new(47);
    let (root_pub, manifest) = identity_group(&root, &c);
    let gid = manifest.group_id.clone();
    let mut book = GroupBook::new();
    ingest(&mut book, &manifest).unwrap();
    let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

    let list = root_list("root-host", 1, vec![c.id()], vec![], root.signing_key());
    let mut root_roster = Roster::new();
    store_list(&mut root_roster, list.clone(), root.signing_key());
    let mut member = Roster::new();
    pin_as(
        &mut member,
        "root-host",
        root.static_key().public_bytes(),
        root.signing_key(),
    );
    store_list(&mut member, list, root.signing_key());
    let crl = root_crl(&member, &root_dev, &root_pub, None).unwrap();
    assert!(matches!(
        book.authorize_group(&gid, &c.id(), &send, NOW, crl.as_ref()),
        Err(CoreError::GroupMemberRevoked(_))
    ));

    rotate_root(&mut root, &mut root_roster, &mut member, "root-host");
    assert_eq!(root_crl(&member, &root_dev, &root_pub, None).unwrap(), None);
}

/// A member that has applied the root's verified rotation fails closed before any re-signed
/// list arrives, whether it holds the founding-key list or no list at all.
#[test]
fn root_crl_fails_closed_on_a_known_rotation_without_a_new_list() {
    for with_list in [true, false] {
        let mut root = runtime_identity(0x34);
        let root_dev = root.device_id();
        let c = Dev::new(48);
        let (root_pub, _) = identity_group(&root, &c);
        let mut member = Roster::new();
        member
            .insert_pinned_host(
                root_dev.clone(),
                "root".to_owned(),
                *root.static_key().public_bytes(),
                Some(root_pub.clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        let before = if with_list {
            let list = root_list(&root_dev, 1, vec![], vec![], root.signing_key());
            store_list(&mut member, list.clone(), root.signing_key());
            Some(list)
        } else {
            None
        };
        assert_eq!(
            root_crl(&member, &root_dev, &root_pub, None).unwrap(),
            before
        );

        root.rotate(
            StaticKeypair::from_scalar([0xE3; 32]),
            SigningKeypair::from_seed([0xE4; 32]),
            NOW,
        )
        .unwrap();
        member
            .apply_verified_rotation(
                &root_dev,
                root.rotation_chain(),
                root.static_key().public_bytes(),
                root.signing_key().public_key(),
            )
            .unwrap();
        let err = root_crl(&member, &root_dev, &root_pub, None).unwrap_err();
        assert!(unauthorized_msg(&err).contains("group root key"), "{err}");
    }
}

/// A core-API root whose `host_id` differs from its `device_id` mints its own list under its
/// `host_id` and has no roster entry of its own; its resolver finds that list through the local
/// label.
#[test]
fn root_crl_reads_a_local_host_labeled_root_list() {
    let root = runtime_identity(0x35).with_host_id("root-host");
    let root_dev = root.device_id();
    let c = Dev::new(49);
    let (root_pub, manifest) = identity_group(&root, &c);
    let gid = manifest.group_id.clone();
    let mut book = GroupBook::new();
    ingest(&mut book, &manifest).unwrap();
    let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

    let mut roster = Roster::new();
    roster.revoke_nonce(&root, "nonce-1", NOW).unwrap();
    store_list(
        &mut roster,
        root_list(
            "root-host",
            2,
            vec![c.id()],
            vec!["nonce-1".to_owned()],
            root.signing_key(),
        ),
        root.signing_key(),
    );
    assert!(roster.get("root-host").is_none());
    assert_eq!(root_crl(&roster, &root_dev, &root_pub, None).unwrap(), None);
    let crl = root_crl(&roster, &root_dev, &root_pub, Some(root.host_id()))
        .unwrap()
        .unwrap();
    assert_eq!(crl.revoked_devices, vec![c.id()]);
    assert!(matches!(
        book.authorize_group(&gid, &c.id(), &send, NOW, Some(&crl)),
        Err(CoreError::GroupMemberRevoked(_))
    ));
}

/// Pins `intruder` under `label` the way an unconfirmed manual pairing does: `Pending`, keyed by
/// the host-chosen `host_id`, claiming `rotation_seq` on a chain of its own.
fn pending_rotated_pin(roster: &mut Roster, label: &str, intruder: &Dev, rotation_seq: u64) {
    roster
        .record_pending_host(
            label.to_owned(),
            "intruder".to_owned(),
            *intruder.st.public_bytes(),
            intruder.sk.public_key().clone(),
            rotation_seq,
            "000000".to_owned(),
            Vec::new(),
        )
        .unwrap();
}

/// An unconfirmed host pin keyed by the local root's own `device_id` never closes the groups the
/// local root founded, whatever rotation it claims.
#[test]
fn root_crl_ignores_a_colliding_pending_pin_on_the_root() {
    for rotation_seq in [1, 5] {
        let root = runtime_identity(0x36);
        let root_dev = root.device_id();
        let c = Dev::new(50);
        let (root_pub, manifest) = identity_group(&root, &c);
        let gid = manifest.group_id.clone();
        let mut book = GroupBook::new();
        ingest(&mut book, &manifest).unwrap();
        let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

        let mut roster = Roster::new();
        pending_rotated_pin(&mut roster, &root_dev, &Dev::new(51), rotation_seq);
        assert_eq!(
            root_crl(&roster, &root_dev, &root_pub, Some(root.host_id())).unwrap(),
            None
        );

        let list = root_list(&root_dev, 1, vec![c.id()], vec![], root.signing_key());
        store_list(&mut roster, list.clone(), root.signing_key());
        let crl = root_crl(&roster, &root_dev, &root_pub, Some(root.host_id())).unwrap();
        assert_eq!(crl, Some(list));
        assert!(matches!(
            book.authorize_group(&gid, &c.id(), &send, NOW, crl.as_ref()),
            Err(CoreError::GroupMemberRevoked(_))
        ));
    }
}

/// An unconfirmed host pin keyed by the local root's own `device_id` counts as no entry, so the
/// local root still fails closed once it rotates and re-signs its list under the new key.
#[test]
fn root_crl_local_root_rotation_fails_closed_under_a_colliding_pending_pin() {
    for rotation_seq in [0, 1] {
        let mut root = runtime_identity(0x38);
        let root_dev = root.device_id();
        let c = Dev::new(54);
        let (root_pub, manifest) = identity_group(&root, &c);
        let gid = manifest.group_id.clone();
        let mut book = GroupBook::new();
        ingest(&mut book, &manifest).unwrap();
        let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

        let mut roster = Roster::new();
        let list = root_list(&root_dev, 1, vec![c.id()], vec![], root.signing_key());
        store_list(&mut roster, list, root.signing_key());
        pending_rotated_pin(&mut roster, &root_dev, &Dev::new(55), rotation_seq);
        let crl = root_crl(&roster, &root_dev, &root_pub, Some(root.host_id())).unwrap();
        assert!(matches!(
            book.authorize_group(&gid, &c.id(), &send, NOW, crl.as_ref()),
            Err(CoreError::GroupMemberRevoked(_))
        ));

        root.rotate(
            StaticKeypair::from_scalar([0xE5; 32]),
            SigningKeypair::from_seed([0xE6; 32]),
            NOW,
        )
        .unwrap();
        roster.resign_crl(&root, NOW).unwrap().unwrap();
        let err = root_crl(&roster, &root_dev, &root_pub, Some(root.host_id())).unwrap_err();
        assert!(unauthorized_msg(&err).contains("group root key"), "{err}");
    }
}

/// A confirmed peer whose remote-chosen `host_id` equals the local root's `device_id` is an
/// `Active` entry at `rotation_seq` 0 and can store a higher-seq list of its own under that
/// label. The local root fails closed rather than treating the group as having no revocations.
#[test]
fn root_crl_local_root_fails_closed_under_a_colliding_active_pin_list() {
    let root = runtime_identity(0x39);
    let root_dev = root.device_id();
    let c = Dev::new(56);
    let (root_pub, manifest) = identity_group(&root, &c);
    let gid = manifest.group_id.clone();
    let mut book = GroupBook::new();
    ingest(&mut book, &manifest).unwrap();
    let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

    let mut roster = Roster::new();
    let list = root_list(&root_dev, 1, vec![c.id()], vec![], root.signing_key());
    store_list(&mut roster, list, root.signing_key());
    let crl = root_crl(&roster, &root_dev, &root_pub, Some(root.host_id())).unwrap();
    assert!(matches!(
        book.authorize_group(&gid, &c.id(), &send, NOW, crl.as_ref()),
        Err(CoreError::GroupMemberRevoked(_))
    ));

    let intruder = Dev::new(57);
    pin_as(
        &mut roster,
        &root_dev,
        intruder.st.public_bytes(),
        &intruder.sk,
    );
    // A newer list keeps earlier revocations (pairing-v1 Section 5.2); this test is about the
    // colliding pin.
    store_list(
        &mut roster,
        root_list(&root_dev, 2, vec![c.id()], vec![], &intruder.sk),
        &intruder.sk,
    );
    let err = root_crl(&roster, &root_dev, &root_pub, Some(root.host_id())).unwrap_err();
    assert!(unauthorized_msg(&err).contains("group root key"), "{err}");
}

/// A member that knows its root under a host label keeps the root list when an unconfirmed,
/// rotated host pin claims the root `device_id` as its label.
#[test]
fn root_crl_ignores_a_colliding_pending_pin_on_a_member() {
    let root = runtime_identity(0x37).with_host_id("root-host");
    let root_dev = root.device_id();
    let c = Dev::new(52);
    let (root_pub, manifest) = identity_group(&root, &c);
    let gid = manifest.group_id.clone();
    let mut book = GroupBook::new();
    ingest(&mut book, &manifest).unwrap();
    let send = Capability::parse(&format!("group.send:{gid}")).unwrap();

    let mut member = Roster::new();
    pin_as(
        &mut member,
        "root-host",
        root.static_key().public_bytes(),
        root.signing_key(),
    );
    let list = root_list("root-host", 1, vec![c.id()], vec![], root.signing_key());
    store_list(&mut member, list.clone(), root.signing_key());
    pending_rotated_pin(&mut member, &root_dev, &Dev::new(53), 1);
    let crl = root_crl(&member, &root_dev, &root_pub, None).unwrap();
    assert_eq!(crl, Some(list));
    assert!(matches!(
        book.authorize_group(&gid, &c.id(), &send, NOW, crl.as_ref()),
        Err(CoreError::GroupMemberRevoked(_))
    ));
}

/// A non-`Pending` entry under the root `device_id` that has rotated keys fails closed even when
/// nothing shows its key lineage starts at the founding root: a roster entry does not record
/// where its lineage started, so it cannot be told apart from the root's own entry. The same keys
/// pinned `Pending` count as no entry. The root's own entry fails closed after each verified
/// rotation.
#[test]
fn root_crl_fails_closed_on_a_rotated_entry_of_unknown_lineage() {
    let mut root = runtime_identity(0x38);
    let root_dev = root.device_id();
    let c = Dev::new(54);
    let (root_pub, _) = identity_group(&root, &c);
    let list = root_list(&root_dev, 1, vec![c.id()], vec![], root.signing_key());

    let intruder = Dev::new(55);
    let mut pending = Roster::new();
    pending_rotated_pin(&mut pending, &root_dev, &intruder, 1);
    assert_eq!(
        root_crl(&pending, &root_dev, &root_pub, None).unwrap(),
        None
    );
    let mut unknown = Roster::new();
    unknown
        .insert_pinned_host(
            root_dev.clone(),
            "intruder".to_owned(),
            *intruder.st.public_bytes(),
            Some(intruder.sk.public_key().clone()),
            1,
            Vec::new(),
        )
        .unwrap();
    let err = root_crl(&unknown, &root_dev, &root_pub, None).unwrap_err();
    assert!(unauthorized_msg(&err).contains("group root key"), "{err}");

    let mut member = Roster::new();
    member
        .insert_pinned_host(
            root_dev.clone(),
            "root".to_owned(),
            *root.static_key().public_bytes(),
            Some(root_pub.clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    store_list(&mut member, list.clone(), root.signing_key());
    assert_eq!(
        root_crl(&member, &root_dev, &root_pub, None).unwrap(),
        Some(list)
    );
    for (scalar, seed) in [(0xE5, 0xE6), (0xE7, 0xE8)] {
        root.rotate(
            StaticKeypair::from_scalar([scalar; 32]),
            SigningKeypair::from_seed([seed; 32]),
            NOW,
        )
        .unwrap();
        member
            .apply_verified_rotation(
                &root_dev,
                root.rotation_chain(),
                root.static_key().public_bytes(),
                root.signing_key().public_key(),
            )
            .unwrap();
        let err = root_crl(&member, &root_dev, &root_pub, None).unwrap_err();
        assert!(unauthorized_msg(&err).contains("group root key"), "{err}");
    }
    assert_eq!(member.get(&root_dev).unwrap().rotation_seq, 2);
}

// Per-peer quota for first-contact group pins.

struct Pinned {
    root: Dev,
    manifest: GroupManifest,
    secrets: V2GroupSecrets,
    grant: tendril_core::grants::Grant,
}

/// A group rooted at a throwaway key (`root_seed`) in which the peer holding `peer_static` and
/// `peer_sk` is a co-admin that signed the manifest adding `local`.
fn co_admin_group(
    root_seed: u8,
    peer_static: &[u8; 32],
    peer_sk: &SigningKeypair,
    local: &Dev,
) -> Pinned {
    let root = Dev::new(root_seed);
    let gid = group_id_from_root(root.sk.public_key());
    let (m1, s1) = tendril_core::group::create_group(
        &root.sk,
        "g",
        2,
        root.member("root", std_caps(&gid)),
        params(),
    )
    .unwrap();
    let peer_id = device_id(peer_static);
    let peer = GroupMember::new(
        peer_static,
        "peer",
        peer_sk.public_key(),
        vec![],
        std_caps(&gid),
    );
    let (m2, s2) = add_member(&m1, &GroupSigner::root(&root.sk), peer, &s1, params()).unwrap();
    let grant = issue_admin_grant(
        &root.sk,
        &root.id(),
        &gid,
        &peer_id,
        peer_sk.public_key(),
        0,
        params(),
    )
    .unwrap();
    let signer = GroupSigner::co_admin(peer_sk, peer_id, grant.clone());
    let (manifest, secrets) = add_member(
        &m2,
        &signer,
        local.member("local", std_caps(&gid)),
        &s2,
        params(),
    )
    .unwrap();
    Pinned {
        root,
        manifest,
        secrets,
        grant,
    }
}

/// Runs the first-contact rule and the quota-checked ingest for a push from `sender`.
fn first_contact_pin(
    book: &mut GroupBook,
    roster: &Roster,
    local: &Dev,
    sender: &str,
    manifest: &GroupManifest,
) -> Result<(), CoreError> {
    let handles = check_first_contact(roster, &local.id(), sender, manifest)?;
    book.ingest_first_contact_manifest(manifest, NOW, None, &handles)
        .map(|_| ())
}

fn quota_refused(r: Result<(), CoreError>) {
    let err = r.unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("pinned by this peer"),
        "{err}"
    );
}

fn pinned_by(book: &GroupBook, gid: &str) -> serde_json::Value {
    serde_json::to_value(book).unwrap()["groups"][gid]["pinned_by"].clone()
}

#[test]
fn first_contact_pins_are_capped_per_peer() {
    let local = Dev::new(3);
    let s = Dev::new(60);
    let t = Dev::new(61);
    let mut roster = Roster::new();
    pin_dev(&mut roster, &s);
    pin_dev(&mut roster, &t);
    let mut book = GroupBook::new();

    // A record created by a plain ingest is not attributed to anyone.
    let plain = co_admin_group(150, s.st.public_bytes(), &s.sk, &local);
    ingest(&mut book, &plain.manifest).unwrap();

    assert_eq!(MAX_GROUPS_PER_SIGNER, 4);
    let mut pins = Vec::new();
    for i in 0..u8::try_from(MAX_GROUPS_PER_SIGNER).unwrap() {
        let g = co_admin_group(151 + i, s.st.public_bytes(), &s.sk, &local);
        first_contact_pin(&mut book, &roster, &local, &s.id(), &g.manifest).unwrap();
        pins.push(g);
    }
    let fifth = co_admin_group(160, s.st.public_bytes(), &s.sk, &local);
    quota_refused(first_contact_pin(
        &mut book,
        &roster,
        &local,
        &s.id(),
        &fifth.manifest,
    ));
    assert!(book.manifest(&fifth.manifest.group_id).is_none());

    let other = co_admin_group(161, t.st.public_bytes(), &t.sk, &local);
    first_contact_pin(&mut book, &roster, &local, &t.id(), &other.manifest).unwrap();

    // Removing the local device keeps the record and its attribution.
    let first = &pins[0];
    let (removed, _) = remove_member(
        &first.manifest,
        &GroupSigner::root(&first.root.sk),
        &local.id(),
        &first.secrets,
        params(),
    )
    .unwrap();
    ingest(&mut book, &removed).unwrap();
    assert!(!book.holds_group(&local.id(), &removed.group_id));
    quota_refused(first_contact_pin(
        &mut book,
        &roster,
        &local,
        &s.id(),
        &fifth.manifest,
    ));

    assert!(book.forget_group(&pins[1].manifest.group_id));
    first_contact_pin(&mut book, &roster, &local, &s.id(), &fifth.manifest).unwrap();
    let sixth = co_admin_group(162, s.st.public_bytes(), &s.sk, &local);
    quota_refused(first_contact_pin(
        &mut book,
        &roster,
        &local,
        &s.id(),
        &sixth.manifest,
    ));
}

#[test]
fn first_contact_pin_without_handles_is_refused() {
    let local = Dev::new(3);
    let s = Dev::new(62);
    let mut book = GroupBook::new();
    let g = co_admin_group(163, s.st.public_bytes(), &s.sk, &local);
    let err = book
        .ingest_first_contact_manifest(&g.manifest, NOW, None, &BTreeSet::new())
        .unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("without peer handles"),
        "{err}"
    );
    assert!(book.manifest(&g.manifest.group_id).is_none());

    // A stored group is an update: quota-exempt, with or without handles.
    ingest(&mut book, &g.manifest).unwrap();
    let (renewed, _) = renew_manifest(
        &g.manifest,
        &GroupSigner::root(&g.root.sk),
        &g.secrets,
        params(),
    )
    .unwrap();
    book.ingest_first_contact_manifest(&renewed, NOW, None, &BTreeSet::new())
        .unwrap();
}

fn alias_by_reverse_pairing(roster: &mut Roster, identity: &EndpointIdentity) {
    roster
        .record_pending_pair(
            *identity.static_key().public_bytes(),
            Some(identity.signing_key().public_key().clone()),
            "peer".to_owned(),
            "peer".to_owned(),
            "1111".to_owned(),
        )
        .unwrap();
    roster
        .confirm_peer(&identity.device_id(), Some("1111"))
        .unwrap();
}

fn rotate_peer(roster: &mut Roster, label: &str, identity: &mut EndpointIdentity) {
    identity
        .rotate(
            StaticKeypair::from_scalar([0xC5; 32]),
            SigningKeypair::from_seed([0xC6; 32]),
            NOW,
        )
        .unwrap();
    roster
        .apply_verified_rotation(
            label,
            identity.rotation_chain(),
            identity.static_key().public_bytes(),
            identity.signing_key().public_key(),
        )
        .unwrap();
}

#[test]
fn quota_survives_alias_and_rotation() {
    let local = Dev::new(3);
    // Host labels that sort before and after the device-id alias, aliases added before or after
    // the pins, and rotation through the host pin or through the alias.
    for host in ["s-host", "a-host"] {
        for alias_first in [false, true] {
            for rotate_via_alias in [false, true] {
                let case = format!("{host} alias_first={alias_first} via_alias={rotate_via_alias}");
                let mut s = runtime_identity(0x50);
                let old_static = *s.static_key().public_bytes();
                let old_sk = SigningKeypair::from_seed([0x50u8.wrapping_add(0x40); 32]);
                let old_id = s.device_id();
                let mut roster = Roster::new();
                pin_as(&mut roster, host, &old_static, &old_sk);
                if alias_first {
                    alias_by_reverse_pairing(&mut roster, &s);
                }
                let mut book = GroupBook::new();
                let mut seed = 170u8;
                let mut next_group = |static_pub: &[u8; 32], sk: &SigningKeypair| {
                    seed += 1;
                    co_admin_group(seed, static_pub, sk, &local).manifest
                };
                for _ in 0..MAX_GROUPS_PER_SIGNER {
                    let m = next_group(&old_static, &old_sk);
                    first_contact_pin(&mut book, &roster, &local, &old_id, &m).unwrap();
                }
                if !alias_first {
                    alias_by_reverse_pairing(&mut roster, &s);
                    let m = next_group(&old_static, &old_sk);
                    let r = first_contact_pin(&mut book, &roster, &local, &old_id, &m);
                    assert!(r.is_err(), "{case}: alias reset the quota");
                    quota_refused(r);
                }

                let label = if rotate_via_alias {
                    old_id.clone()
                } else {
                    host.to_owned()
                };
                rotate_peer(&mut roster, &label, &mut s);
                let new_static = *s.static_key().public_bytes();
                let new_sk = SigningKeypair::from_seed([0xC6; 32]);
                let m = next_group(&new_static, &new_sk);
                let r = first_contact_pin(&mut book, &roster, &local, &s.device_id(), &m);
                assert!(r.is_err(), "{case}: rotation reset the quota");
                quota_refused(r);
                let m = next_group(&old_static, &old_sk);
                let r = first_contact_pin(&mut book, &roster, &local, &old_id, &m);
                assert!(r.is_err(), "{case}: the unrotated entry reset the quota");
                quota_refused(r);
            }
        }
    }
}

/// Documented residual (`docs/design/groups.md` Known limitations "Per-peer pin quota"): a peer
/// that gains a new roster entry after reaching the cap (here a host pin under a new label) and
/// rotates through that entry only shares no handle with its earlier records and starts a new
/// quota.
#[test]
fn quota_residual_late_host_alias_rotation() {
    let local = Dev::new(3);
    let mut s = runtime_identity(0x51);
    let old_static = *s.static_key().public_bytes();
    let old_sk = SigningKeypair::from_seed([0x51u8.wrapping_add(0x40); 32]);
    let old_id = s.device_id();
    let mut roster = Roster::new();
    pin_as(&mut roster, "s-host", &old_static, &old_sk);
    let mut book = GroupBook::new();
    for i in 0..u8::try_from(MAX_GROUPS_PER_SIGNER).unwrap() {
        let g = co_admin_group(190 + i, &old_static, &old_sk, &local);
        first_contact_pin(&mut book, &roster, &local, &old_id, &g.manifest).unwrap();
    }
    pin_as(&mut roster, "s-host2", &old_static, &old_sk);
    let g = co_admin_group(195, &old_static, &old_sk, &local);
    quota_refused(first_contact_pin(
        &mut book,
        &roster,
        &local,
        &old_id,
        &g.manifest,
    ));

    rotate_peer(&mut roster, "s-host2", &mut s);
    let new_sk = SigningKeypair::from_seed([0xC6; 32]);
    let g = co_admin_group(196, s.static_key().public_bytes(), &new_sk, &local);
    first_contact_pin(&mut book, &roster, &local, &s.device_id(), &g.manifest).unwrap();
}

#[test]
fn updates_at_quota_are_exempt_but_verified() {
    let local = Dev::new(3);
    let s = Dev::new(62);
    let mut roster = Roster::new();
    pin_dev(&mut roster, &s);
    let mut book = GroupBook::new();
    let mut pins = Vec::new();
    for i in 0..u8::try_from(MAX_GROUPS_PER_SIGNER).unwrap() {
        let g = co_admin_group(200 + i, s.st.public_bytes(), &s.sk, &local);
        first_contact_pin(&mut book, &roster, &local, &s.id(), &g.manifest).unwrap();
        pins.push(g);
    }
    let g = &pins[0];
    let gid = g.manifest.group_id.clone();
    let attribution = pinned_by(&book, &gid);
    assert!(attribution.as_array().is_some_and(|a| !a.is_empty()));
    let handles = check_first_contact(&roster, &local.id(), &s.id(), &pins[1].manifest).unwrap();
    let update = |book: &mut GroupBook, m: &GroupManifest| {
        book.ingest_first_contact_manifest(m, NOW, None, &handles)
            .map(|_| ())
    };
    let still_capped = |book: &mut GroupBook, seed: u8| {
        let extra = co_admin_group(seed, s.st.public_bytes(), &s.sk, &local);
        quota_refused(first_contact_pin(
            book,
            &roster,
            &local,
            &s.id(),
            &extra.manifest,
        ));
    };

    // A valid co-admin update and a root-signed update are accepted at the cap.
    let co = GroupSigner::co_admin(&s.sk, s.id(), g.grant.clone());
    let (m4, s4) = renew_manifest(&g.manifest, &co, &g.secrets, params()).unwrap();
    update(&mut book, &m4).unwrap();
    let root = GroupSigner::root(&g.root.sk);
    let (m5, s5) = renew_manifest(&m4, &root, &s4, params()).unwrap();
    update(&mut book, &m5).unwrap();
    assert_eq!(book.manifest(&gid).unwrap().seq, m5.seq);
    assert_eq!(pinned_by(&book, &gid), attribution);
    still_capped(&mut book, 210);

    // Every other ingest rule still applies.
    assert!(matches!(
        update(&mut book, &m4),
        Err(CoreError::GroupSeqRollback { .. })
    ));
    let (fork, _) = renew_manifest(&m4, &root, &s4, GroupBuildParams::new(NOW + 5)).unwrap();
    assert_eq!(fork.seq, m5.seq);
    assert!(matches!(
        update(&mut book, &fork),
        Err(CoreError::GroupManifestFork { .. })
    ));
    let alter_root = co_signed(&m5, &s, &g.grant, |u| {
        let entry = u
            .members
            .iter_mut()
            .find(|m| m.device_id == g.root.id())
            .unwrap();
        entry.name = "renamed".to_owned();
    });
    let err = update(&mut book, &alter_root).unwrap_err();
    assert!(
        unauthorized_msg(&err).contains("founding root entry"),
        "{err}"
    );
    let (m6, _) = remove_member(&m5, &root, &local.id(), &s5, params()).unwrap();
    update(&mut book, &m6).unwrap();
    let mut unrevoke = m6.unsigned();
    unrevoke.seq += 1;
    unrevoke.revoked_members.clear();
    let unrevoke = sign_group_manifest(unrevoke, &g.root.sk).unwrap();
    assert!(update(&mut book, &unrevoke).is_err());
    assert_eq!(book.manifest(&gid).unwrap().seq, m6.seq);
    assert_eq!(pinned_by(&book, &gid), attribution);
    still_capped(&mut book, 211);
}

#[test]
fn group_book_pinned_by_round_trips_and_old_books_load() {
    let local = Dev::new(3);
    let s = Dev::new(63);
    let mut roster = Roster::new();
    pin_dev(&mut roster, &s);
    let mut book = GroupBook::new();
    let g = co_admin_group(220, s.st.public_bytes(), &s.sk, &local);
    first_contact_pin(&mut book, &roster, &local, &s.id(), &g.manifest).unwrap();
    let json = serde_json::to_string(&book).unwrap();
    assert!(json.contains("\"pinned_by\""));
    let back: GroupBook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, book);

    // A book written before attribution existed loads, and its records count for nobody.
    let mut old: serde_json::Value = serde_json::from_str(&json).unwrap();
    old["groups"][&g.manifest.group_id]
        .as_object_mut()
        .unwrap()
        .remove("pinned_by");
    let mut old: GroupBook = serde_json::from_value(old).unwrap();
    assert!(pinned_by(&old, &g.manifest.group_id).is_null());
    for i in 0..u8::try_from(MAX_GROUPS_PER_SIGNER).unwrap() {
        let g = co_admin_group(221 + i, s.st.public_bytes(), &s.sk, &local);
        first_contact_pin(&mut old, &roster, &local, &s.id(), &g.manifest).unwrap();
    }
}
