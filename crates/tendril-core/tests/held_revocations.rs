//! `Roster::absorb_held_revocations`: the fold that carries the revocation state an in-memory
//! roster holds into the on-disk roster (`spec/pairing-v1.md` Section 5.2).
//!
//! `disk` is the roster as stored, `memory` the copy live sessions write to.

use tendril_core::crypto::{
    HybridSigningPublicKey, SigningKeypair, StaticKeypair, b64url_encode, device_id,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::identity::{EndpointIdentity, sign_rotation};
use tendril_core::roster::{
    AnchorState, OperatorEndpoint, PeerState, Roster, StaticResolution, V2PeerSecrets,
};

const NOW: u64 = 1_795_000_000;
const TTL: u64 = 2_592_000;

struct Peer {
    static_pub: [u8; 32],
    sk: SigningKeypair,
}

impl Peer {
    fn new(seed: u8) -> Self {
        Self {
            static_pub: *StaticKeypair::from_scalar([seed; 32]).public_bytes(),
            sk: SigningKeypair::from_seed([seed.wrapping_add(1); 32]),
        }
    }

    fn pubkey(&self) -> HybridSigningPublicKey {
        self.sk.public_key().clone()
    }
}

fn pin(roster: &mut Roster, label: &str, peer: &Peer) {
    roster
        .insert_pinned_host(
            label.into(),
            "Peer".into(),
            peer.static_pub,
            Some(peer.pubkey()),
            0,
            vec![],
        )
        .unwrap();
}

fn pin_with_secret(roster: &mut Roster, label: &str, peer: &Peer, secret: u8) {
    pin(roster, label, peer);
    roster
        .set_peer_v2_secrets(label, V2PeerSecrets::new([secret; 32], [secret ^ 0xFF; 32]))
        .unwrap();
}

fn crl(issuer: &str, seq: u64, signer: &SigningKeypair, revoked: &[&str]) -> RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: issuer.into(),
            seq,
            revoked_devices: revoked.iter().map(|s| (*s).to_owned()).collect(),
            revoked_nonces: vec![],
            ts: "2026-11-20T00:00:00Z".into(),
        },
        signer,
    )
    .unwrap()
}

fn bytes(roster: &Roster) -> Vec<u8> {
    serde_json::to_vec(roster).unwrap()
}

fn state(roster: &Roster, id: &str) -> Option<PeerState> {
    roster.get(id).map(|e| e.state)
}

fn notice_json(roster: &Roster, id: &str) -> Option<serde_json::Value> {
    roster
        .get(id)
        .and_then(|e| e.refusal_notice())
        .map(|n| serde_json::to_value(n).unwrap())
}

fn notice_until(roster: &Roster, id: &str) -> Option<u64> {
    roster
        .get(id)
        .and_then(|e| e.refusal_notice())
        .map(|n| n.until_unix())
}

fn is_revoked(roster: &Roster, static_pub: &[u8; 32]) -> bool {
    matches!(
        roster.resolve_static(static_pub),
        StaticResolution::Revoked(_)
    )
}

/// `roster` as stored JSON with `edit` applied, loaded back.
fn reload(roster: &Roster, edit: impl FnOnce(&mut serde_json::Value)) -> Roster {
    let mut json = serde_json::to_value(roster).unwrap();
    edit(&mut json);
    serde_json::from_value(json).unwrap()
}

/// Folds `memory` into `disk`, and checks the fold is idempotent byte for byte.
fn fold(disk: &mut Roster, memory: &Roster, local: Option<(&str, &HybridSigningPublicKey)>) {
    disk.absorb_held_revocations(memory, local);
    let once = bytes(disk);
    assert!(
        !disk.absorb_held_revocations(memory, local),
        "a second fold changed the roster"
    );
    assert_eq!(bytes(disk), once, "a second fold is not a byte no-op");
}

fn secret_b64(byte: u8) -> String {
    b64url_encode(&[byte; 32])
}

fn secret_of(roster: &Roster, id: &str) -> Option<String> {
    notice_json(roster, id).and_then(|n| n["secret"].as_str().map(str::to_owned))
}

// ---------------------------------------------------------------------------------------------
// Notices (Section 3.1.4)
// ---------------------------------------------------------------------------------------------

/// Peers a..f, `Active` with v2 secrets, on both sides.
fn notice_base() -> (Roster, [(String, Peer); 6]) {
    let peers = [0x10u8, 0x12, 0x14, 0x16, 0x18, 0x1a].map(Peer::new);
    let labels = ["peer-a", "peer-b", "peer-c", "peer-d", "peer-e", "peer-f"];
    let mut base = Roster::new();
    for (i, (label, peer)) in labels.iter().zip(&peers).enumerate() {
        pin_with_secret(&mut base, label, peer, 0x30 + u8::try_from(i).unwrap());
    }
    let named = labels
        .iter()
        .zip(peers)
        .map(|(l, p)| ((*l).to_owned(), p))
        .collect::<Vec<_>>();
    (base, named.try_into().ok().unwrap())
}

#[test]
fn revoked_on_disk_with_a_notice_and_silently_revoked_in_memory_has_none() {
    let (base, _) = notice_base();
    let mut disk = base.clone();
    disk.revoke_peer_at("peer-a", true, NOW).unwrap();
    assert!(notice_json(&disk, "peer-a").is_some());
    let mut memory = disk.clone();
    memory.revoke_peer("peer-a").unwrap();
    assert!(notice_json(&memory, "peer-a").is_none());

    fold(&mut disk, &memory, None);
    assert_eq!(state(&disk, "peer-a"), Some(PeerState::Revoked));
    assert!(
        notice_json(&disk, "peer-a").is_none(),
        "memory saw a clearing event"
    );
}

#[test]
fn revoked_on_disk_with_a_notice_keeps_it_unchanged() {
    let (base, _) = notice_base();
    // Memory still has the peer active.
    let memory = base.clone();
    let mut disk = base.clone();
    disk.revoke_peer_at("peer-a", true, NOW).unwrap();
    let before = notice_json(&disk, "peer-a");
    fold(&mut disk, &memory, None);
    assert_eq!(notice_json(&disk, "peer-a"), before);

    // Memory revoked it later, with a notice of its own: never extended.
    let mut memory = base.clone();
    memory.revoke_peer_at("peer-b", true, NOW + 5_000).unwrap();
    let mut disk = base.clone();
    disk.revoke_peer_at("peer-b", true, NOW).unwrap();
    fold(&mut disk, &memory, None);
    assert_eq!(notice_until(&disk, "peer-b"), Some(NOW + TTL));

    // Memory never saw the entry at all.
    let mut disk = base.clone();
    disk.revoke_peer_at("peer-c", true, NOW).unwrap();
    let before = notice_json(&disk, "peer-c");
    fold(&mut disk, &Roster::new(), None);
    assert_eq!(notice_json(&disk, "peer-c"), before);
}

#[test]
fn revoked_on_disk_without_a_notice_never_gets_one() {
    let (base, _) = notice_base();
    let mut disk = base.clone();
    disk.revoke_peer("peer-a").unwrap();
    let mut memory = base.clone();
    memory.revoke_peer_at("peer-a", true, NOW).unwrap();
    assert!(notice_json(&memory, "peer-a").is_some());
    fold(&mut disk, &memory, None);
    assert_eq!(state(&disk, "peer-a"), Some(PeerState::Revoked));
    assert!(notice_json(&disk, "peer-a").is_none());
}

#[test]
fn active_on_disk_takes_the_notice_memory_recorded() {
    let (base, _) = notice_base();
    let mut memory = base.clone();
    memory.revoke_peer_at("peer-a", true, NOW + 77).unwrap();
    let mut disk = base.clone();
    fold(&mut disk, &memory, None);
    assert_eq!(state(&disk, "peer-a"), Some(PeerState::Revoked));
    assert_eq!(
        notice_until(&disk, "peer-a"),
        Some(NOW + 77 + TTL),
        "carried as recorded, never recomputed"
    );
}

#[test]
fn the_refusal_secret_comes_from_the_disk_entry() {
    let (base, _) = notice_base();
    let mut memory = base.clone();
    // Memory holds a different reconnect secret than disk for the same entry.
    memory
        .set_peer_v2_secrets("peer-a", V2PeerSecrets::new([0x77; 32], [0x78; 32]))
        .unwrap();
    memory.revoke_peer_at("peer-a", true, NOW).unwrap();
    assert_eq!(secret_of(&memory, "peer-a"), Some(secret_b64(0x77)));
    let mut disk = base.clone();
    fold(&mut disk, &memory, None);
    assert_eq!(
        secret_of(&disk, "peer-a"),
        Some(secret_b64(0x30)),
        "the disk entry's reconnect_secret"
    );
}

#[test]
fn no_notice_without_one_in_memory_or_for_a_new_record() {
    let (base, _) = notice_base();
    // Memory revoked silently, or revoked a sibling: no notice. Absent on disk: none either.
    let mut memory = base.clone();
    memory.revoke_peer("peer-a").unwrap();
    let late = Peer::new(0x50);
    pin_with_secret(&mut memory, "born-in-memory", &late, 0x51);
    memory.revoke_peer_at("born-in-memory", true, NOW).unwrap();
    let mut disk = base.clone();
    fold(&mut disk, &memory, None);
    assert_eq!(state(&disk, "peer-a"), Some(PeerState::Revoked));
    assert!(notice_json(&disk, "peer-a").is_none());
    assert_eq!(state(&disk, "born-in-memory"), Some(PeerState::Revoked));
    assert!(notice_json(&disk, "born-in-memory").is_none());
}

#[test]
fn sibling_order_never_decides_the_primarys_notice() {
    // BTreeMap order puts the label that sorts first ahead of the other; try both ways.
    for (primary, sibling) in [("zz-primary", "aa-sibling"), ("aa-primary", "zz-sibling")] {
        let shared = Peer::new(0x60);
        let mut base = Roster::new();
        pin_with_secret(&mut base, primary, &shared, 0x61);
        pin_with_secret(&mut base, sibling, &shared, 0x62);
        let mut memory = base.clone();
        memory.revoke_peer_at(primary, true, NOW).unwrap();
        assert!(notice_json(&memory, primary).is_some());
        assert_eq!(state(&memory, sibling), Some(PeerState::Revoked));
        assert!(notice_json(&memory, sibling).is_none());

        let mut disk = base.clone();
        fold(&mut disk, &memory, None);
        assert_eq!(state(&disk, primary), Some(PeerState::Revoked), "{primary}");
        assert_eq!(
            notice_until(&disk, primary),
            Some(NOW + TTL),
            "the primary keeps its notice with {sibling} first or last"
        );
        assert!(notice_json(&disk, sibling).is_none());
    }
}

#[test]
fn a_local_crl_ingested_with_notify_keeps_its_notices_through_the_fold() {
    let (base, _) = notice_base();
    let local = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x71; 32]),
        SigningKeypair::from_seed([0x72; 32]),
    )
    .with_host_id("local-host");
    let local_pub = local.signing_key().public_key().clone();
    let mut memory = base.clone();
    memory
        .ingest_crl_at(
            crl("local-host", 1, local.signing_key(), &["peer-a"]),
            "local-host",
            &local_pub,
            true,
            NOW,
        )
        .unwrap();
    assert!(notice_json(&memory, "peer-a").is_some());

    let mut disk = base.clone();
    fold(&mut disk, &memory, Some(("local-host", &local_pub)));
    assert_eq!(state(&disk, "peer-a"), Some(PeerState::Revoked));
    assert_eq!(
        notice_until(&disk, "peer-a"),
        Some(NOW + TTL),
        "the silent re-ingest of the CRL does not wipe the notice"
    );
    assert_eq!(disk.crl("local-host").map(|c| c.seq), Some(1));
}

// ---------------------------------------------------------------------------------------------
// CRLs (Sections 3.1.1 and 3.2)
// ---------------------------------------------------------------------------------------------

#[test]
fn the_local_hosts_own_crl_is_carried_only_with_a_local_key() {
    let local = Peer::new(0x80);
    let victim = Peer::new(0x82);
    let mut base = Roster::new();
    pin(&mut base, "victim", &victim);
    let mut memory = base.clone();
    memory
        .ingest_crl(
            crl("local-host", 1, &local.sk, &["victim"]),
            "local-host",
            &local.pubkey(),
        )
        .unwrap();

    let mut without = base.clone();
    without.absorb_held_revocations(&memory, None);
    assert!(without.crl("local-host").is_none());

    let local_pub = local.pubkey();
    let mut disk = base.clone();
    fold(&mut disk, &memory, Some(("local-host", &local_pub)));
    assert_eq!(disk.crl("local-host").map(|c| c.seq), Some(1));
    assert_eq!(state(&disk, "victim"), Some(PeerState::Revoked));
}

#[test]
fn a_revoked_issuers_and_a_revoked_anchors_crl_are_carried() {
    let peer = Peer::new(0x84);
    let anchor = Peer::new(0x86);
    let mut base = Roster::new();
    pin(&mut base, "issuer-p", &peer);
    base.add_trust_anchor("anchor-a".into(), anchor.pubkey())
        .unwrap();
    let mut memory = base.clone();
    memory
        .ingest_crl(
            crl("issuer-p", 1, &peer.sk, &["x"]),
            "issuer-p",
            &peer.pubkey(),
        )
        .unwrap();
    memory
        .ingest_crl(
            crl("anchor-a", 1, &anchor.sk, &["y"]),
            "anchor-a",
            &anchor.pubkey(),
        )
        .unwrap();
    // Both issuers are revoked on disk (and in memory) before the CRLs are committed.
    let mut disk = base.clone();
    disk.revoke_peer("issuer-p").unwrap();
    disk.revoke_trust_anchor("anchor-a").unwrap();
    memory.revoke_peer("issuer-p").unwrap();
    memory.revoke_trust_anchor("anchor-a").unwrap();

    fold(&mut disk, &memory, None);
    assert_eq!(disk.crl("issuer-p").map(|c| c.seq), Some(1));
    assert_eq!(disk.crl("anchor-a").map(|c| c.seq), Some(1));
}

#[test]
fn a_key_rotated_on_disk_still_verifies_a_held_crl_through_the_held_entry() {
    let old = Peer::new(0x88);
    let new = Peer::new(0x8a);
    let fork_a = Peer::new(0x8c);
    let fork_b = Peer::new(0x8e);
    let mut base = Roster::new();
    pin(&mut base, "rotating", &old);
    // Memory revokes the peer by a fork and holds a CRL signed by its old key.
    let mut memory = base.clone();
    let rec_a = sign_rotation(1, &old.sk, &fork_a.pubkey(), &fork_a.static_pub, NOW).unwrap();
    let rec_b = sign_rotation(1, &old.sk, &fork_b.pubkey(), &fork_b.static_pub, NOW + 1).unwrap();
    let res = memory.apply_verified_rotation(
        "rotating",
        &[rec_a, rec_b],
        &fork_a.static_pub,
        &fork_a.pubkey(),
    );
    assert!(matches!(res, Err(CoreError::RotationForkDetected { .. })));
    memory
        .ingest_crl(
            crl("rotating", 1, &old.sk, &["other"]),
            "rotating",
            &old.pubkey(),
        )
        .unwrap();
    // Disk rotated the peer to a new key, so no key on disk verifies the CRL.
    let mut disk = base.clone();
    let rec = sign_rotation(1, &old.sk, &new.pubkey(), &new.static_pub, NOW).unwrap();
    disk.apply_verified_rotation("rotating", &[rec], &new.static_pub, &new.pubkey())
        .unwrap();

    fold(&mut disk, &memory, None);
    assert_eq!(disk.crl("rotating").map(|c| c.seq), Some(1));
}

#[test]
fn an_issuer_matches_a_peer_by_its_device_id_on_disk_and_in_memory() {
    let key = Peer::new(0x90);
    let mut one = Roster::new();
    pin(&mut one, "alias-x", &key);
    one.revoke_peer("alias-x").unwrap();
    let edit = |roster: &Roster| {
        reload(roster, |json| {
            json["entries"]["alias-x"]["device_id"] = "issuer-y".into();
        })
    };
    let relabelled = edit(&one);
    assert_eq!(relabelled.get("alias-x").unwrap().device_id, "issuer-y");
    let mut signer = Roster::new();
    signer
        .ingest_crl(
            crl("issuer-y", 1, &key.sk, &["z"]),
            "issuer-y",
            &key.pubkey(),
        )
        .unwrap();

    // Candidate 3: the entry on disk, found by `device_id`.
    let mut disk = relabelled.clone();
    fold(&mut disk, &signer, None);
    assert_eq!(disk.crl("issuer-y").map(|c| c.seq), Some(1));

    // Candidate 5: the entry only in memory, found by `device_id`.
    let mut memory = relabelled.clone();
    memory
        .ingest_crl(
            crl("issuer-y", 1, &key.sk, &["z"]),
            "issuer-y",
            &key.pubkey(),
        )
        .unwrap();
    let mut disk = Roster::new();
    fold(&mut disk, &memory, None);
    assert_eq!(disk.crl("issuer-y").map(|c| c.seq), Some(1));
}

#[test]
fn a_pending_entrys_key_never_verifies_a_crl() {
    let claimed = Peer::new(0x94);
    let id = device_id(&claimed.static_pub);
    let mut base = Roster::new();
    base.record_pending_pair(
        claimed.static_pub,
        Some(claimed.pubkey()),
        "C".into(),
        "cli".into(),
        "sas".into(),
    )
    .unwrap();
    assert_eq!(state(&base, &id), Some(PeerState::Pending));
    // A CRL signed by the pending claim's key, held by memory.
    let mut memory = base.clone();
    memory
        .ingest_crl(
            crl(&id, 1, &claimed.sk, &["victim"]),
            &id,
            &claimed.pubkey(),
        )
        .unwrap();

    let mut disk = base.clone();
    assert!(!disk.absorb_held_revocations(&memory, None));
    assert!(
        disk.crl(&id).is_none(),
        "an unconfirmed claim has no authority"
    );
    assert_eq!(bytes(&disk), bytes(&base));
}

#[test]
fn an_equal_or_lower_seq_changes_nothing() {
    let peer = Peer::new(0x98);
    let mut base = Roster::new();
    pin(&mut base, "issuer-p", &peer);
    let mut disk = base.clone();
    disk.ingest_crl(
        crl("issuer-p", 5, &peer.sk, &["a"]),
        "issuer-p",
        &peer.pubkey(),
    )
    .unwrap();
    let before = bytes(&disk);
    for seq in [5, 3, 1] {
        let mut memory = base.clone();
        memory
            .ingest_crl(
                crl("issuer-p", seq, &peer.sk, &["b"]),
                "issuer-p",
                &peer.pubkey(),
            )
            .unwrap();
        assert!(!disk.absorb_held_revocations(&memory, None), "seq {seq}");
        assert_eq!(bytes(&disk), before, "seq {seq}");
    }
    assert_eq!(disk.crl("issuer-p").unwrap().seq, 5);

    // A higher seq is taken.
    let mut memory = base.clone();
    memory
        .ingest_crl(
            crl("issuer-p", 6, &peer.sk, &["c"]),
            "issuer-p",
            &peer.pubkey(),
        )
        .unwrap();
    fold(&mut disk, &memory, None);
    assert_eq!(disk.crl("issuer-p").unwrap().seq, 6);
}

#[test]
fn a_peer_named_like_the_local_host_cannot_write_the_local_crl() {
    let local = Peer::new(0xa0);
    let attacker = Peer::new(0xa2);
    let victim = Peer::new(0xa4);
    let mut base = Roster::new();
    pin(&mut base, "local-host", &attacker);
    pin(&mut base, "victim", &victim);
    let mut memory = base.clone();
    memory
        .ingest_crl(
            crl("local-host", u64::MAX, &attacker.sk, &["victim"]),
            "local-host",
            &attacker.pubkey(),
        )
        .unwrap();

    let local_pub = local.pubkey();
    let mut disk = base.clone();
    disk.absorb_held_revocations(&memory, Some(("local-host", &local_pub)));
    assert!(disk.crl("local-host").is_none(), "the attacker's CRL");

    // The local host's genuine CRL is not wedged behind a `u64::MAX` seq.
    disk.ingest_crl(
        crl("local-host", 1, &local.sk, &["victim"]),
        "local-host",
        &local_pub,
    )
    .unwrap();
    assert_eq!(disk.crl("local-host").map(|c| c.seq), Some(1));
}

// ---------------------------------------------------------------------------------------------
// Entries and anchors (Sections 3.1.2 and 3.1.3)
// ---------------------------------------------------------------------------------------------

#[test]
fn an_entry_born_in_memory_is_inserted_revoked_and_carries_nothing_else() {
    let born = Peer::new(0xb0);
    let mut memory = Roster::new();
    memory
        .insert_pinned_host(
            "born".into(),
            "Born".into(),
            born.static_pub,
            Some(born.pubkey()),
            0,
            vec!["wss://relay.example/v1/relay".into()],
        )
        .unwrap();
    memory
        .set_peer_v2_secrets("born", V2PeerSecrets::new([1; 32], [2; 32]))
        .unwrap();
    memory
        .set_routes(
            "born",
            vec![OperatorEndpoint {
                hint: "direct:127.0.0.1:7000".into(),
                relay_key: None,
            }],
        )
        .unwrap();
    memory.revoke_peer_at("born", true, NOW).unwrap();

    let mut disk = Roster::new();
    fold(&mut disk, &memory, None);
    let entry = disk.get("born").expect("inserted");
    assert_eq!(entry.state, PeerState::Revoked);
    assert_eq!(entry.static_pub, born.static_pub);
    assert_eq!(entry.signing_pub, Some(born.pubkey()));
    assert!(entry.routes.is_empty());
    assert!(entry.route_meta.is_none());
    assert!(entry.relay_hints.is_empty());
    assert!(entry.grants.is_empty());
    assert!(entry.v2_secrets.is_none());
    assert!(entry.last_pairing_sas.is_none());
    assert!(entry.refusal_notice().is_none());
    assert!(is_revoked(&disk, &born.static_pub));
}

#[test]
fn a_revoked_claim_tombstone_and_its_siblings_are_carried() {
    let claim = Peer::new(0xb4);
    let sibling = Peer {
        static_pub: *StaticKeypair::from_scalar([0xb6; 32]).public_bytes(),
        // Shares the claim's signing identity.
        sk: SigningKeypair::from_seed([0xb5; 32]),
    };
    let mut base = Roster::new();
    pin(&mut base, "sibling", &sibling);
    let mut memory = base.clone();
    memory
        .record_pending_host(
            "claimed".into(),
            "Claim".into(),
            claim.static_pub,
            claim.pubkey(),
            0,
            "123456".into(),
            vec![],
        )
        .unwrap();
    memory
        .revoke_pending_host(&device_id(&claim.static_pub))
        .unwrap();
    assert!(is_revoked(&memory, &claim.static_pub));

    let mut disk = base.clone();
    fold(&mut disk, &memory, None);
    assert!(is_revoked(&disk, &claim.static_pub));
    assert!(
        disk.entries()
            .any(|(k, e)| k.contains("#revoked-") && e.static_pub == claim.static_pub),
        "the tombstone"
    );
    assert_eq!(state(&disk, "sibling"), Some(PeerState::Revoked));
}

/// `K` is `Active` on disk with new keys after a valid rotation, and `Revoked` in memory with its
/// old keys after a fork: the old keys must stay revoked.
fn rotated_on_disk_revoked_in_memory(label_of: impl Fn(&Peer) -> String) {
    let old = Peer::new(0xc0);
    let fresh = Peer::new(0xc2);
    let fork_a = Peer::new(0xc4);
    let fork_b = Peer::new(0xc6);
    let label = label_of(&old);
    let mut base = Roster::new();
    pin(&mut base, &label, &old);

    let mut memory = base.clone();
    let rec_a = sign_rotation(1, &old.sk, &fork_a.pubkey(), &fork_a.static_pub, NOW).unwrap();
    let rec_b = sign_rotation(1, &old.sk, &fork_b.pubkey(), &fork_b.static_pub, NOW + 1).unwrap();
    let res = memory.apply_verified_rotation(
        &label,
        &[rec_a, rec_b],
        &fork_a.static_pub,
        &fork_a.pubkey(),
    );
    assert!(matches!(res, Err(CoreError::RotationForkDetected { .. })));
    assert_eq!(state(&memory, &label), Some(PeerState::Revoked));

    let mut disk = base.clone();
    let rec = sign_rotation(1, &old.sk, &fresh.pubkey(), &fresh.static_pub, NOW).unwrap();
    disk.apply_verified_rotation(&label, &[rec], &fresh.static_pub, &fresh.pubkey())
        .unwrap();
    assert_eq!(state(&disk, &label), Some(PeerState::Active));

    fold(&mut disk, &memory, None);
    assert!(is_revoked(&disk, &old.static_pub), "the old static key");
    assert!(is_revoked(&disk, &fresh.static_pub), "the rotated key");
    let prefix = format!("{}#revoked-", device_id(&old.static_pub));
    assert!(
        disk.entries().any(|(k, e)| k.starts_with(&prefix)
            && e.state == PeerState::Revoked
            && e.static_pub == old.static_pub
            && e.signing_pub == Some(old.pubkey())),
        "a tombstone holds the old keys"
    );
}

#[test]
fn rotated_on_disk_while_revoked_in_memory() {
    rotated_on_disk_revoked_in_memory(|_| "host-k".to_owned());
    rotated_on_disk_revoked_in_memory(|old| device_id(&old.static_pub));
}

#[test]
fn a_pending_entry_replaced_on_disk_stays_revoked_in_memory() {
    let claimed = Peer::new(0xd0);
    let replacement = Peer::new(0xd2);
    let id = device_id(&claimed.static_pub);
    let mut base = Roster::new();
    base.record_pending_pair(
        claimed.static_pub,
        Some(claimed.pubkey()),
        "C".into(),
        "cli".into(),
        "sas".into(),
    )
    .unwrap();
    let mut memory = base.clone();
    memory.revoke_peer(&id).unwrap();
    assert!(is_revoked(&memory, &claimed.static_pub));

    // Disk replaced the same label with a pinned host holding fresh keys.
    let mut disk = Roster::new();
    pin(&mut disk, &id, &replacement);
    assert_eq!(state(&disk, &id), Some(PeerState::Active));

    fold(&mut disk, &memory, None);
    assert!(is_revoked(&disk, &claimed.static_pub));
    assert!(is_revoked(&disk, &replacement.static_pub));
}

#[test]
fn revoked_on_disk_with_different_keys_revokes_an_active_entry_sharing_the_held_signing_key() {
    let old = Peer::new(0xe0);
    let fresh = Peer::new(0xe2);
    let fork_a = Peer::new(0xe4);
    let fork_b = Peer::new(0xe6);
    // `sharer` has its own static key but the old signing identity.
    let sharer = Peer {
        static_pub: *StaticKeypair::from_scalar([0xe8; 32]).public_bytes(),
        sk: SigningKeypair::from_seed([0xe1; 32]),
    };
    let mut base = Roster::new();
    pin(&mut base, "host-k", &old);

    let mut memory = base.clone();
    let rec_a = sign_rotation(1, &old.sk, &fork_a.pubkey(), &fork_a.static_pub, NOW).unwrap();
    let rec_b = sign_rotation(1, &old.sk, &fork_b.pubkey(), &fork_b.static_pub, NOW + 1).unwrap();
    let _ = memory.apply_verified_rotation(
        "host-k",
        &[rec_a, rec_b],
        &fork_a.static_pub,
        &fork_a.pubkey(),
    );

    // On disk K was rotated and then revoked: its old keys are gone from the entry.
    let mut disk = base.clone();
    let rec = sign_rotation(1, &old.sk, &fresh.pubkey(), &fresh.static_pub, NOW).unwrap();
    disk.apply_verified_rotation("host-k", &[rec], &fresh.static_pub, &fresh.pubkey())
        .unwrap();
    disk.revoke_peer("host-k").unwrap();
    // Only disk knows `sharer`, which holds the old signing identity.
    pin(&mut disk, "sharer", &sharer);
    assert_eq!(state(&disk, "sharer"), Some(PeerState::Active));

    fold(&mut disk, &memory, None);
    assert_eq!(state(&disk, "sharer"), Some(PeerState::Revoked));
    assert!(disk.lookup_active_signing_key("sharer").is_none());
}

#[test]
fn revoked_on_disk_with_a_different_anchor_key_blocks_the_held_key() {
    let held_key = Peer::new(0xf0);
    let disk_key = Peer::new(0xf2);
    let sharer = Peer {
        static_pub: *StaticKeypair::from_scalar([0xf4; 32]).public_bytes(),
        sk: SigningKeypair::from_seed([0xf1; 32]),
    };
    let mut memory = Roster::new();
    memory
        .add_trust_anchor("anchor-a".into(), held_key.pubkey())
        .unwrap();
    memory.revoke_trust_anchor("anchor-a").unwrap();

    let mut disk = Roster::new();
    disk.add_trust_anchor("anchor-a".into(), disk_key.pubkey())
        .unwrap();
    disk.revoke_trust_anchor("anchor-a").unwrap();
    pin(&mut disk, "sharer", &sharer);

    fold(&mut disk, &memory, None);
    assert_eq!(state(&disk, "sharer"), Some(PeerState::Revoked));
    assert!(matches!(
        disk.add_trust_anchor("fresh-anchor".into(), held_key.pubkey()),
        Err(CoreError::PeerRevoked(_))
    ));
    assert!(
        disk.trust_anchors()
            .any(|(id, a)| id.starts_with("anchor-a#revoked-")
                && a.state == AnchorState::Revoked
                && a.signing_pub == held_key.pubkey()),
        "the anchor tombstone"
    );
}

#[test]
fn an_anchor_revoked_in_memory_is_revoked_on_disk_or_inserted() {
    let on_disk = Peer::new(0xf8);
    let missing = Peer::new(0xfa);
    // Shares the signing key of the anchor only memory knows, under its own static key.
    let sharer = Peer {
        static_pub: *StaticKeypair::from_scalar([0xfc; 32]).public_bytes(),
        sk: SigningKeypair::from_seed([0xfb; 32]),
    };
    assert_eq!(sharer.pubkey(), missing.pubkey());
    let mut base = Roster::new();
    base.add_trust_anchor("anchor-d".into(), on_disk.pubkey())
        .unwrap();
    let mut memory = base.clone();
    memory.revoke_trust_anchor("anchor-d").unwrap();
    memory
        .add_trust_anchor("anchor-m".into(), missing.pubkey())
        .unwrap();
    memory.revoke_trust_anchor("anchor-m").unwrap();

    let mut disk = base.clone();
    fold(&mut disk, &memory, None);
    assert_eq!(
        disk.trust_anchor("anchor-d").map(|a| a.state),
        Some(AnchorState::Revoked),
        "an active anchor on disk"
    );
    assert_eq!(
        disk.trust_anchor("anchor-m").map(|a| a.state),
        Some(AnchorState::Revoked),
        "an anchor absent on disk"
    );

    let mut with_sharer = base.clone();
    pin(&mut with_sharer, "sharer", &sharer);
    fold(&mut with_sharer, &memory, None);
    assert_eq!(
        state(&with_sharer, "sharer"),
        Some(PeerState::Revoked),
        "an entry sharing an inserted anchor's signing key"
    );
}

// ---------------------------------------------------------------------------------------------
// What never crosses (INV-3)
// ---------------------------------------------------------------------------------------------

#[test]
fn nothing_but_revocation_state_crosses_to_disk() {
    let a = Peer::new(0x40);
    let b = Peer::new(0x42);
    let mut base = Roster::new();
    pin(&mut base, "peer-a", &a);
    pin(&mut base, "peer-b", &b);
    let mut disk = base.clone();
    disk.set_routes(
        "peer-a",
        vec![OperatorEndpoint {
            hint: "direct:127.0.0.1:7001".into(),
            relay_key: None,
        }],
    )
    .unwrap();
    let before = bytes(&disk);

    // Memory changed routes and added an `Active` peer and a nonce; none of it is revocation state.
    let mut memory = base.clone();
    memory
        .set_routes(
            "peer-a",
            vec![OperatorEndpoint {
                hint: "direct:127.0.0.1:7002".into(),
                relay_key: None,
            }],
        )
        .unwrap();
    pin(&mut memory, "memory-only", &Peer::new(0x44));
    memory
        .burn_enrollment_nonce("nonce-1", NOW + 100, NOW)
        .unwrap();
    assert!(!disk.absorb_held_revocations(&memory, None));
    assert_eq!(bytes(&disk), before);
}

#[test]
fn a_held_revoked_state_is_never_lowered_by_the_fold() {
    let a = Peer::new(0x46);
    let mut base = Roster::new();
    pin(&mut base, "peer-a", &a);
    let mut disk = base.clone();
    disk.revoke_peer("peer-a").unwrap();
    // Memory still holds the peer `Active`: the fold never un-revokes it.
    let memory = base.clone();
    assert!(!disk.absorb_held_revocations(&memory, None));
    assert_eq!(state(&disk, "peer-a"), Some(PeerState::Revoked));
}
