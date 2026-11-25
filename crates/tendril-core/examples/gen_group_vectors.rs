//! Generates `spec/vectors/groups.json` from deterministic keys using real hybrid signatures.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use tendril_core::crypto::{
    SigningKeypair, StaticKeypair, b64url_encode, device_id, x25519_public_from_scalar,
};
use tendril_core::grants::{GrantUnsigned, grant_signed_bytes, sign_grant_deterministic};
use tendril_core::group::{
    GroupBuildParams, GroupManifest, GroupManifestUnsigned, GroupMember, GroupSeq, GroupSigner,
    V2GroupSecrets, add_member, create_group_with_signer, derive_group_mailbox_secret,
    derive_pair_bootstrap, encode_group_rendezvous_frame, group_id_from_root,
    group_manifest_signed_bytes, issue_admin_grant_deterministic, remove_member_with_key,
    verify_group_manifest,
};
use tendril_core::wire::{InnerFrameType, SessionHello, encode_inner_frame};

const NOW: u64 = 1_795_564_800;

struct Dev {
    st: StaticKeypair,
    sk: SigningKeypair,
    st_seed: u8,
    sk_seed: u8,
}

impl Dev {
    fn new(seed: u8) -> Self {
        let mut scalar = [seed; 32];
        scalar[0] = seed ^ 0x5A;
        Self {
            st: StaticKeypair::from_scalar(scalar),
            sk: SigningKeypair::from_seed([seed.wrapping_add(0x80); 32]),
            st_seed: seed,
            sk_seed: seed.wrapping_add(0x80),
        }
    }

    fn id(&self) -> String {
        device_id(self.st.public_bytes())
    }

    fn member(&self, name: &str, gid: &str) -> GroupMember {
        GroupMember::new(
            self.st.public_bytes(),
            name,
            self.sk.public_key(),
            vec!["wss://relay.example/v2/relay".to_string()],
            vec![format!("group.send:{gid}"), format!("group.recv:{gid}")],
        )
    }

    fn json(&self) -> Value {
        let mut scalar = [self.st_seed; 32];
        scalar[0] = self.st_seed ^ 0x5A;
        json!({
            "device_id": self.id(),
            "static_scalar_hex": hex::encode(scalar),
            "static_pub_hex": hex::encode(x25519_public_from_scalar(&scalar)),
            "signing_seed_hex": hex::encode([self.sk_seed; 32]),
            "signing_pub_hex": hex::encode(self.sk.public_bytes()),
        })
    }
}

fn manifest_entry(label: &str, m: &GroupManifest) -> Result<Value, Box<dyn std::error::Error>> {
    let unsigned = m.unsigned();
    let signed = group_manifest_signed_bytes(&unsigned)?;
    Ok(json!({
        "label": label,
        "manifest": m,
        "signed_bytes_hex": hex::encode(&signed),
        "wire_len": m.to_wire_bytes()?.len(),
    }))
}

fn rejection(name: &str, error: &str, m: &Value, prior_index: Option<usize>) -> Value {
    json!({
        "name": name,
        "expected_error": error,
        "manifest": m,
        "prior_index": prior_index,
    })
}

fn raw_sign(unsigned: GroupManifestUnsigned, key: &SigningKeypair) -> GroupManifest {
    let msg = group_manifest_signed_bytes(&unsigned).expect("signed bytes");
    let sig = key.sign_deterministic(&msg).expect("sign");
    GroupManifest {
        v: unsigned.v,
        group_id: unsigned.group_id,
        name: unsigned.name,
        seq: unsigned.seq,
        min_wire_version: unsigned.min_wire_version,
        ts: unsigned.ts,
        expires_at: unsigned.expires_at,
        root_signing_pub: unsigned.root_signing_pub,
        signer_device_id: unsigned.signer_device_id,
        signer_signing_pub: unsigned.signer_signing_pub,
        admin_grant: unsigned.admin_grant,
        members: unsigned.members,
        revoked_members: unsigned.revoked_members,
        sig: b64url_encode(&sig),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let params = GroupBuildParams::new(NOW);

    let root = Dev::new(1);
    let co_admin = Dev::new(2);
    let dev_a = Dev::new(3);
    let dev_b = Dev::new(4);
    let dev_c = Dev::new(5);
    let gid = group_id_from_root(root.sk.public_key());
    let key = [0x5Au8; 32];
    let rsigner = || GroupSigner::root(&root.sk).deterministic();

    let (m1, s1) = create_group_with_signer(
        &rsigner(),
        "home-cluster",
        2,
        root.member("root", &gid),
        params,
        V2GroupSecrets::new(key, 1),
    )?;
    let (m2, s2) = add_member(&m1, &rsigner(), dev_a.member("laptop", &gid), &s1, params)?;
    let (m3, s3) = add_member(&m2, &rsigner(), dev_b.member("phone", &gid), &s2, params)?;
    let (m3b, s3b) = add_member(
        &m3,
        &rsigner(),
        co_admin.member("tablet", &gid),
        &s3,
        params,
    )?;
    let grant = issue_admin_grant_deterministic(
        &root.sk,
        &root.id(),
        &gid,
        &co_admin.id(),
        co_admin.sk.public_key(),
        0,
        params,
        [0x77; 16],
    )?;
    let co_signer =
        GroupSigner::co_admin(&co_admin.sk, co_admin.id(), grant.clone()).deterministic();
    let (m5, s5) = add_member(&m3b, &co_signer, dev_c.member("watch", &gid), &s3b, params)?;
    let (m6, s6) = remove_member_with_key(&m5, &rsigner(), &dev_b.id(), &s5, [0x6B; 32], params)?;
    for m in [&m1, &m2, &m3, &m3b, &m5, &m6] {
        verify_group_manifest(m, NOW, None)?;
    }
    let chain = [&m1, &m2, &m3, &m3b, &m5, &m6];
    let chain_json = chain
        .iter()
        .enumerate()
        .map(|(i, m)| manifest_entry(&format!("seq{}", i + 1), m))
        .collect::<Result<Vec<_>, _>>()?;
    // chain indices: 0=m1 .. 2=m3 (seq3) 3=m3b (seq4) 4=m5 (seq5, co-admin) 5=m6 (seq6, B revoked)

    let to_value = |m: &GroupManifest| serde_json::to_value(m).expect("manifest json");
    let mut rejections = Vec::new();

    let mut scope = m1.unsigned();
    scope.members[0].caps = vec!["fs.read:/etc/passwd".to_string()];
    rejections.push(rejection(
        "scope_escape_host_path",
        "InvalidGroupCapabilityScope",
        &to_value(&raw_sign(scope, &root.sk)),
        None,
    ));

    let mut cross = m1.unsigned();
    cross.members[0].caps = vec!["group.send:grp_ffffffffffffffff".to_string()];
    rejections.push(rejection(
        "cross_group_capability",
        "InvalidGroupCapabilityScope",
        &to_value(&raw_sign(cross, &root.sk)),
        None,
    ));

    rejections.push(rejection(
        "seq_rollback",
        "GroupSeqRollback",
        &to_value(&m2),
        Some(2),
    ));

    let mut forked = m6.unsigned();
    forked.name = "home-cluster-fork".to_string();
    rejections.push(rejection(
        "same_seq_different_bytes_fork",
        "GroupManifestFork",
        &to_value(&raw_sign(forked, &root.sk)),
        Some(5),
    ));
    let same_seq_replays = vec![json!({
        "name": "identical_replay_is_unchanged",
        "manifest": to_value(&m6),
        "prior_index": 5,
    })];

    let mut readd = m6.unsigned();
    readd.seq = 7;
    readd.revoked_members.clear();
    readd.members.push(dev_b.member("phone", &gid));
    rejections.push(rejection(
        "revoked_member_readded",
        "GroupMemberRevoked",
        &to_value(&raw_sign(readd, &root.sk)),
        Some(5),
    ));

    let mut no_root = m5.unsigned();
    no_root.seq = 6;
    no_root.members.retain(|m| m.device_id != root.id());
    rejections.push(rejection(
        "co_admin_removes_root",
        "InvalidGroupManifest",
        &to_value(&raw_sign(no_root, &co_admin.sk)),
        Some(4),
    ));

    let mut downgrade = m6.unsigned();
    downgrade.seq = 7;
    downgrade.min_wire_version = 1;
    rejections.push(rejection(
        "wire_downgrade",
        "GroupWireDowngrade",
        &to_value(&raw_sign(downgrade, &root.sk)),
        Some(5),
    ));

    let mut many = m1.unsigned();
    for i in 0..32u8 {
        let d = Dev::new(100 + i);
        many.members.push(d.member(&format!("m{i}"), &gid));
    }
    assert_eq!(many.members.len(), 33);
    rejections.push(rejection(
        "too_many_members_33",
        "InvalidGroupManifest",
        &to_value(&raw_sign(many, &root.sk)),
        None,
    ));

    let mut big = m1.unsigned();
    for i in 0..24u8 {
        let d = Dev::new(140 + i);
        let mut member = d.member(&format!("m{i}"), &gid);
        member.endpoints = (0..8)
            .map(|e| {
                let base = format!("wss://relay{e}.example/");
                format!("{base}{}", "a".repeat(200 - base.len()))
            })
            .collect();
        big.members.push(member);
    }
    let oversize = raw_sign(big, &root.sk);
    assert!(oversize.to_wire_bytes().is_err());
    rejections.push(rejection(
        "manifest_oversize",
        "GroupManifestTooLarge",
        &to_value(&oversize),
        None,
    ));

    let mut mismatch = m1.unsigned();
    mismatch.group_id = "grp_0000000000000000".to_string();
    rejections.push(rejection(
        "group_id_mismatch",
        "InvalidGroupManifest",
        &to_value(&raw_sign(mismatch, &root.sk)),
        None,
    ));

    let mut expired = m1.unsigned();
    expired.ts = "2026-10-01T00:00:00Z".to_string();
    expired.expires_at = "2026-10-31T00:00:00Z".to_string();
    rejections.push(rejection(
        "manifest_expired",
        "InvalidGroupManifest",
        &to_value(&raw_sign(expired, &root.sk)),
        None,
    ));

    let attacker = Dev::new(9);
    let mut forged = m3b.unsigned();
    forged.seq = 5;
    forged.signer_device_id = co_admin.id();
    forged.signer_signing_pub = Some(attacker.sk.public_key().to_b64url());
    forged.admin_grant = Some(grant.clone());
    forged.members.retain(|m| m.device_id != co_admin.id());
    forged.members.push(GroupMember::new(
        co_admin.st.public_bytes(),
        "tablet",
        attacker.sk.public_key(),
        vec!["wss://relay.example/v2/relay".to_string()],
        vec![format!("group.send:{gid}"), format!("group.recv:{gid}")],
    ));
    rejections.push(rejection(
        "forged_co_admin_swapped_key",
        "GroupUnauthorized",
        &to_value(&raw_sign(forged, &attacker.sk)),
        Some(3),
    ));

    let bare_grant = sign_grant_deterministic(
        GrantUnsigned {
            caps: vec![format!("group.admin:{gid}")],
            ..grant.unsigned()
        },
        &root.sk,
    )?;
    let mut bare = m3b.unsigned();
    bare.seq = 5;
    bare.signer_device_id = co_admin.id();
    bare.signer_signing_pub = Some(co_admin.sk.public_key().to_b64url());
    bare.admin_grant = Some(bare_grant);
    rejections.push(rejection(
        "bare_admin_grant_not_keyed",
        "GroupUnauthorized",
        &to_value(&raw_sign(bare, &co_admin.sk)),
        Some(3),
    ));

    let mut seq_max = m1.unsigned();
    seq_max.seq = 1 << 53;
    rejections.push(rejection(
        "seq_2_pow_53",
        "InvalidGroupManifest",
        &to_value(&raw_sign(seq_max, &root.sk)),
        None,
    ));

    let mut jump = m1.unsigned();
    jump.seq = 1026;
    rejections.push(rejection(
        "seq_jump_exceeds_1024",
        "InvalidGroupManifest",
        &to_value(&raw_sign(jump, &root.sk)),
        Some(0),
    ));

    let mut dropped = m6.unsigned();
    dropped.seq = 7;
    dropped.members.retain(|m| m.device_id != dev_a.id());
    rejections.push(rejection(
        "removed_member_not_revoked",
        "InvalidGroupManifest",
        &to_value(&raw_sign(dropped, &root.sk)),
        Some(5),
    ));

    let mut rewrite = m3b.unsigned();
    rewrite.seq = 5;
    rewrite.signer_device_id = co_admin.id();
    rewrite.signer_signing_pub = Some(co_admin.sk.public_key().to_b64url());
    rewrite.admin_grant = Some(grant.clone());
    rewrite.members[0].endpoints = vec!["wss://evil.example/v2/relay".to_string()];
    rejections.push(rejection(
        "co_admin_rewrites_root_entry",
        "GroupUnauthorized",
        &to_value(&raw_sign(rewrite, &co_admin.sk)),
        Some(3),
    ));

    for (name, cap) in [
        ("cap_percent_escape", format!("sync.push:{gid}/a%2e%2e")),
        ("cap_backslash", format!("sync.push:{gid}/a\\b")),
    ] {
        let mut escape = m1.unsigned();
        escape.members[0].caps = vec![cap];
        rejections.push(rejection(
            name,
            "InvalidGroupCapabilityScope",
            &to_value(&raw_sign(escape, &root.sk)),
            None,
        ));
    }

    let mut parse_rejections = Vec::new();
    let mut null_grant = to_value(&m1);
    null_grant["admin_grant"] = Value::Null;
    parse_rejections.push(json!({"name": "explicit_null_admin_grant", "manifest": null_grant}));
    let mut null_signer = to_value(&m5);
    null_signer["signer_signing_pub"] = Value::Null;
    parse_rejections
        .push(json!({"name": "explicit_null_signer_signing_pub", "manifest": null_signer}));

    let mut tampered = to_value(&m3);
    tampered["name"] = json!("tampered");
    rejections.push(rejection(
        "tampered_after_signing",
        "InvalidSignature",
        &tampered,
        None,
    ));

    let key_a = [0x11u8; 32];
    let id_x = dev_a.id();
    let id_y = dev_b.id();
    let info_rdv = {
        let (lo, hi) = if id_x <= id_y {
            (&id_x, &id_y)
        } else {
            (&id_y, &id_x)
        };
        let mut v = b"tendril-group-v2-rendezvous\0".to_vec();
        v.extend_from_slice(lo.as_bytes());
        v.push(0);
        v.extend_from_slice(hi.as_bytes());
        v
    };
    let bootstrap = derive_pair_bootstrap(&key_a, 7, &id_x, &id_y);
    assert_eq!(*bootstrap, *derive_pair_bootstrap(&key_a, 7, &id_y, &id_x));
    let mailbox = derive_group_mailbox_secret(&key_a, 7, &id_x);
    let mut info_mb = b"tendril-group-v2-mailbox".to_vec();
    info_mb.extend_from_slice(id_x.as_bytes());

    let frame = encode_group_rendezvous_frame(&gid, 6, s6.group_rendezvous_key())?;
    let inner = encode_inner_frame(InnerFrameType::GroupRendezvous, &frame[..])?;
    let hello = SessionHello {
        device_id: dev_a.id(),
        grant: None,
        crl_seq: None,
        groups: Some(vec![
            GroupSeq {
                group_id: gid.clone(),
                seq: 6,
            },
            GroupSeq {
                group_id: "grp_0123456789abcdef".to_string(),
                seq: 1,
            },
        ]),
        route_seq: None,
        upgrade: Vec::new(),
    };

    let admin_unsigned = grant.unsigned();
    let doc = json!({
        "now_unix": NOW,
        "manifest_domain_hex": hex::encode(b"tendril-group-v1\0"),
        "keys": {
            "root": root.json(),
            "co_admin": co_admin.json(),
            "member_a": dev_a.json(),
            "member_b": dev_b.json(),
            "member_c": dev_c.json(),
        },
        "group_id": {
            "root_signing_pub_hex": hex::encode(root.sk.public_bytes()),
            "root_signing_pub_sha256_hex": hex::encode(Sha256::digest(root.sk.public_bytes())),
            "group_id": gid,
        },
        "limits": {
            "max_members": 32,
            "max_manifest_len": 32768,
            "max_member_endpoints": 8,
            "max_member_caps": 16,
            "max_revoked_members": 256,
            "max_validity_secs": 90 * 86400,
            "max_seq": (1u64 << 53) - 1,
            "max_seq_jump": 1024,
        },
        "chain": chain_json,
        "admin_grant": {
            "grant": grant,
            "signed_bytes_hex": hex::encode(grant_signed_bytes(&admin_unsigned)?),
        },
        "rejections": rejections,
        "same_seq_replays": same_seq_replays,
        "parse_rejections": parse_rejections,
        "pair_bootstrap": {
            "group_rendezvous_key_hex": hex::encode(key_a),
            "seq": 7,
            "id_a": id_x,
            "id_b": id_y,
            "info_hex": hex::encode(&info_rdv),
            "output_hex": hex::encode(*bootstrap),
        },
        "group_mailbox": {
            "group_rendezvous_key_hex": hex::encode(key_a),
            "seq": 7,
            "member_device_id": id_x,
            "info_hex": hex::encode(&info_mb),
            "output_hex": hex::encode(*mailbox),
        },
        "rendezvous_frame": {
            "group_id": gid,
            "seq": 6,
            "group_rendezvous_key_hex": hex::encode(s6.group_rendezvous_key()),
            "frame_hex": hex::encode(&frame[..]),
            "inner_frame_hex": hex::encode(&inner),
        },
        "session_hello_groups": {
            "json": serde_json::to_string(&hello)?,
        },
    });

    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    fs::write(dir.join("groups.json"), text)?;
    Ok(())
}
