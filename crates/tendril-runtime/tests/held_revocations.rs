//! Held revocations on a store-backed [`RosterAccess`]: a commit, a reload and an update never
//! lose a revocation the in-memory roster holds, and never write when there is nothing new
//! (`spec/pairing-v1.md` Section 5.2).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::tempdir;
use tendril_core::crypto::{HybridSigningPublicKey, SigningKeypair, StaticKeypair, device_id};
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::identity::RotationRecord;
use tendril_core::identity::{EndpointIdentity, sign_rotation};
use tendril_core::roster::{
    AnchorState, OperatorEndpoint, PeerState, Roster, RosterEntry, StaticResolution, V2PeerSecrets,
};
use tendril_runtime::{
    AddressSource, AdvertiseInputs, AdvertiseMode, RosterAccess, RouteAnnouncer, RuntimeError,
    StateStore,
};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn lock(roster: &Mutex<Roster>) -> std::sync::MutexGuard<'_, Roster> {
    roster
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn local_identity() -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x80; 32]),
        SigningKeypair::from_seed([0x81; 32]),
    )
    .with_host_id("local-host")
}

fn static_of(seed: u8) -> [u8; 32] {
    *StaticKeypair::from_scalar([seed; 32]).public_bytes()
}

fn sk_of(seed: u8) -> SigningKeypair {
    SigningKeypair::from_seed([seed; 32])
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

fn pin(roster: &mut Roster, label: &str, static_seed: u8, sign_seed: u8) {
    roster
        .insert_pinned_host(
            label.into(),
            "Peer".into(),
            static_of(static_seed),
            Some(sk_of(sign_seed).public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    roster
        .set_peer_v2_secrets(
            label,
            V2PeerSecrets::new([static_seed; 32], [static_seed ^ 0xFF; 32]),
        )
        .unwrap();
}

fn store_in(dir: &std::path::Path) -> Arc<StateStore> {
    Arc::new(StateStore::open_or_create(dir).unwrap())
}

fn access_with_signer(store: &Arc<StateStore>) -> RosterAccess {
    let local = local_identity();
    RosterAccess::from_store(Arc::clone(store))
        .unwrap()
        .with_local_signer(local.host_id(), local.signing_key().public_key().clone())
}

fn stamp(store: &StateStore) -> Option<tendril_runtime::RosterStamp> {
    store.roster_stamp().unwrap()
}

fn is_revoked(roster: &Roster, static_pub: &[u8; 32]) -> bool {
    matches!(
        roster.resolve_static(static_pub),
        StaticResolution::Revoked(_)
    )
}

fn has_tombstone(roster: &Roster, static_pub: &[u8; 32]) -> bool {
    let prefix = format!("{}#revoked-", device_id(static_pub));
    roster
        .entries()
        .any(|(k, e)| k.starts_with(&prefix) && e.state == PeerState::Revoked)
}

// ---------------------------------------------------------------------------------------------
// API behaviour
// ---------------------------------------------------------------------------------------------

#[test]
fn session_commit_keeps_revoked_anchor_crls_and_memory_only_revocations() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    let anchor_key = sk_of(0x60);
    store
        .update_roster(|r| {
            r.add_trust_anchor("anchor-a".into(), anchor_key.public_key().clone())?;
            pin(r, "peer-q", 0x20, 0x21);
            r.record_pending_host(
                "claimed".into(),
                "Claim".into(),
                static_of(0x70),
                sk_of(0x71).public_key().clone(),
                0,
                "123456".into(),
                vec![],
            )?;
            Ok(())
        })
        .unwrap();
    let access = access_with_signer(&store);
    {
        let mut mem = lock(access.roster());
        mem.ingest_crl(
            crl("anchor-a", 1, &anchor_key, &["nobody"]),
            "anchor-a",
            anchor_key.public_key(),
        )
        .unwrap();
        mem.revoke_trust_anchor("anchor-a").unwrap();
        mem.revoke_peer("peer-q").unwrap();
        mem.revoke_pending_host(&device_id(&static_of(0x70)))
            .unwrap();
    }
    assert!(store.load_roster().unwrap().crl("anchor-a").is_none());

    assert!(access.commit_held_revocations().unwrap());

    let fresh = RosterAccess::from_store(Arc::new(StateStore::open_or_create(dir.path()).unwrap()))
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(fresh.crl("anchor-a").map(|c| c.seq), Some(1), "A's CRL");
    assert_eq!(
        fresh.trust_anchor("anchor-a").map(|a| a.state),
        Some(AnchorState::Revoked),
        "revoked A"
    );
    assert_eq!(
        fresh.get("peer-q").map(|e| e.state),
        Some(PeerState::Revoked),
        "memory-only revoked Q"
    );
    assert!(has_tombstone(&fresh, &static_of(0x70)), "the tombstone");

    let before = stamp(&store);
    assert!(
        !access.commit_held_revocations().unwrap(),
        "a second commit has nothing new"
    );
    assert_eq!(stamp(&store), before, "and writes nothing");
}

#[test]
fn a_commit_with_nothing_new_creates_no_file() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    let access = access_with_signer(&store);
    assert!(!access.commit_held_revocations().unwrap());
    assert!(
        stamp(&store).is_none(),
        "no roster.json for an empty roster"
    );

    // An active peer in memory is not revocation state.
    lock(access.roster())
        .insert_pinned_host(
            "peer-a".into(),
            "A".into(),
            static_of(0x22),
            Some(sk_of(0x23).public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    assert!(!access.commit_held_revocations().unwrap());
    assert!(stamp(&store).is_none());
}

#[test]
fn update_if_changed_persists_a_held_revocation_even_when_nothing_else_changed() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    store
        .update_roster(|r| {
            pin(r, "peer-q", 0x20, 0x21);
            Ok(())
        })
        .unwrap();
    let access = access_with_signer(&store);
    lock(access.roster()).revoke_peer("peer-q").unwrap();
    assert_eq!(
        store.load_roster().unwrap().get("peer-q").map(|e| e.state),
        Some(PeerState::Active)
    );

    access.update_if_changed(|_| Ok(((), false))).unwrap();
    assert_eq!(
        store.load_roster().unwrap().get("peer-q").map(|e| e.state),
        Some(PeerState::Revoked)
    );

    let before = stamp(&store);
    access.update_if_changed(|_| Ok(((), false))).unwrap();
    assert_eq!(
        stamp(&store),
        before,
        "an unchanged roster is not rewritten"
    );
}

#[test]
fn reload_keeps_held_revocations_and_never_writes() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    store
        .update_roster(|r| {
            pin(r, "peer-q", 0x20, 0x21);
            Ok(())
        })
        .unwrap();
    let access = access_with_signer(&store);
    lock(access.roster()).revoke_peer("peer-q").unwrap();
    // Another handle changes the disk meanwhile.
    store
        .update_roster(|r| {
            pin(r, "peer-new", 0x24, 0x25);
            Ok(())
        })
        .unwrap();
    let before = stamp(&store);

    access.reload().unwrap();
    assert_eq!(stamp(&store), before, "a reload never writes");
    let mem = lock(access.roster());
    assert_eq!(mem.get("peer-q").map(|e| e.state), Some(PeerState::Revoked));
    assert!(
        mem.get("peer-new").is_some(),
        "memory takes the disk roster"
    );
}

#[test]
fn load_keeps_the_local_hosts_own_crl_only_with_a_signer() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    store
        .update_roster(|r| {
            pin(r, "peer-a", 0x20, 0x21);
            Ok(())
        })
        .unwrap();
    let local = local_identity();
    let local_pub = local.signing_key().public_key().clone();
    let with_signer = access_with_signer(&store);
    let without = RosterAccess::from_store(Arc::clone(&store)).unwrap();
    for access in [&with_signer, &without] {
        lock(access.roster())
            .ingest_crl(
                crl("local-host", 1, local.signing_key(), &["peer-a"]),
                "local-host",
                &local_pub,
            )
            .unwrap();
    }
    assert_eq!(
        with_signer.load().unwrap().crl("local-host").map(|c| c.seq),
        Some(1)
    );
    assert!(without.load().unwrap().crl("local-host").is_none());
}

#[test]
fn a_failed_transaction_still_persists_revoked_anchors_and_crls() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    let anchor_key = sk_of(0x60);
    store
        .update_roster(|r| {
            r.add_trust_anchor("anchor-a".into(), anchor_key.public_key().clone())?;
            pin(r, "peer-a", 0x20, 0x21);
            Ok(())
        })
        .unwrap();
    let local = local_identity();
    let local_pub = local.signing_key().public_key().clone();
    let failing = |r: &mut Roster| -> Result<(), RuntimeError> {
        r.revoke_trust_anchor("anchor-a")?;
        r.ingest_crl(
            crl("local-host", 1, local.signing_key(), &["peer-a"]),
            "local-host",
            &local_pub,
        )?;
        pin(r, "not-persisted", 0x30, 0x31);
        Err(RuntimeError::Storage("boom".into()))
    };

    store
        .update_roster_persisting_revocations(failing)
        .unwrap_err();
    let disk = store.load_roster().unwrap();
    assert_eq!(
        disk.trust_anchor("anchor-a").map(|a| a.state),
        Some(AnchorState::Revoked)
    );
    assert_eq!(
        disk.get("peer-a").map(|e| e.state),
        Some(PeerState::Revoked),
        "revoked by the CRL"
    );
    assert!(disk.crl("local-host").is_none(), "no local key was named");
    assert!(disk.get("not-persisted").is_none(), "nothing else persists");

    store
        .update_roster_persisting_revocations_with(Some(("local-host", &local_pub)), |r| {
            r.ingest_crl(
                crl("local-host", 1, local.signing_key(), &["peer-a"]),
                "local-host",
                &local_pub,
            )?;
            Err::<(), _>(RuntimeError::Storage("boom".into()))
        })
        .unwrap_err();
    assert_eq!(
        store
            .load_roster()
            .unwrap()
            .crl("local-host")
            .map(|c| c.seq),
        Some(1)
    );
}

/// A route publish and a reload or commit run concurrently: the published local routes never
/// differ between memory and disk, and no revocation is lost.
#[test]
fn a_route_publish_racing_a_reload_and_a_commit_never_clobbers() {
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    store
        .update_roster(|r| {
            pin(r, "peer-q", 0x20, 0x21);
            Ok(())
        })
        .unwrap();
    let access = access_with_signer(&store);
    lock(access.roster()).revoke_peer("peer-q").unwrap();
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x11; 32]),
        SigningKeypair::from_seed([0x12; 32]),
    )
    .with_host_id("host-race");
    let ann = Arc::new(RouteAnnouncer::new(
        host,
        access.clone(),
        AdvertiseInputs::default(),
        AddressSource::Native,
    ));
    let inputs = |i: usize| AdvertiseInputs {
        mode: AdvertiseMode::Explicit,
        advertised_endpoints: vec![format!("192.168.7.{}:9100", 1 + i % 2)],
        ..AdvertiseInputs::default()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let (access, stop) = (access.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                access.reload().unwrap();
                access.commit_held_revocations().unwrap();
            }
        })
    };
    for i in 0..200 {
        ann.set_inputs(inputs(i));
        ann.publish(1_700_000_000_000 + u64::try_from(i).unwrap() * 1_000)
            .unwrap();
    }
    stop.store(true, Ordering::Release);
    churn.join().unwrap();

    let disk = store.load_roster().unwrap();
    let mem = lock(access.roster()).clone();
    let routes = |r: &Roster| r.local_routes().map(|s| (s.seq(), *s.digest()));
    assert!(routes(&disk).is_some());
    assert_eq!(routes(&mem), routes(&disk), "memory and disk agree");
    assert_eq!(mem.get("peer-q").map(|e| e.state), Some(PeerState::Revoked));
    assert_eq!(
        disk.get("peer-q").map(|e| e.state),
        Some(PeerState::Revoked)
    );
}

// ---------------------------------------------------------------------------------------------
// Property round trip
// ---------------------------------------------------------------------------------------------

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

const PEERS: usize = 4;
const ANCHORS: usize = 2;
const CLAIMS: usize = 2;
const CRL_SEQS: u64 = 3;

fn peer_label(i: usize) -> String {
    format!("peer-{i}")
}

fn anchor_label(i: usize) -> String {
    format!("anchor-{i}")
}

fn peer_seed(i: usize) -> u8 {
    0x20 + u8::try_from(i).unwrap()
}

fn peer_sk(i: usize) -> SigningKeypair {
    sk_of(0x40 + u8::try_from(i).unwrap())
}

fn anchor_sk(i: usize) -> SigningKeypair {
    sk_of(0x60 + u8::try_from(i).unwrap())
}

fn claim_static(i: usize) -> [u8; 32] {
    static_of(0x70 + u8::try_from(i).unwrap())
}

fn claim_sk(i: usize) -> SigningKeypair {
    sk_of(0x72 + u8::try_from(i).unwrap())
}

/// Fresh keys `2 * peer + variant`: rotation targets and fork branches.
fn fresh_static(n: usize) -> [u8; 32] {
    static_of(0x90 + u8::try_from(n).unwrap())
}

fn fresh_sk(n: usize) -> SigningKeypair {
    sk_of(0xa0 + u8::try_from(n).unwrap())
}

/// Everything the random runs sign, built once: signing is the expensive step.
struct Fixtures {
    /// `rotations[peer][variant]`: the record from the peer's initial key to the fresh keys.
    rotations: Vec<[RotationRecord; 2]>,
    /// Issuer index (peers, anchors, local), then seq `1..=CRL_SEQS`, then target peer.
    crls: Vec<Vec<Vec<RevocationList>>>,
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let local = local_identity();
        let rotations = (0..PEERS)
            .map(|i| {
                [0, 1].map(|v| {
                    let n = 2 * i + v;
                    sign_rotation(
                        1,
                        &peer_sk(i),
                        fresh_sk(n).public_key(),
                        &fresh_static(n),
                        1_795_000_000,
                    )
                    .unwrap()
                })
            })
            .collect();
        let targets: Vec<String> = (0..PEERS).map(peer_label).collect();
        let issuer = |id: &str, signer: &SigningKeypair| -> Vec<Vec<RevocationList>> {
            (1..=CRL_SEQS)
                .map(|seq| {
                    targets
                        .iter()
                        .map(|t| crl(id, seq, signer, &[t.as_str()]))
                        .collect()
                })
                .collect()
        };
        let mut crls: Vec<Vec<Vec<RevocationList>>> = (0..PEERS)
            .map(|i| issuer(&peer_label(i), &peer_sk(i)))
            .collect();
        crls.extend((0..ANCHORS).map(|i| issuer(&anchor_label(i), &anchor_sk(i))));
        crls.push(issuer("local-host", local.signing_key()));
        Fixtures { rotations, crls }
    })
}

fn seed_disk(store: &StateStore) {
    store
        .update_roster(|r| {
            for i in 0..PEERS {
                pin(
                    r,
                    &peer_label(i),
                    peer_seed(i),
                    0x40 + u8::try_from(i).unwrap(),
                );
            }
            for i in 0..ANCHORS {
                r.add_trust_anchor(anchor_label(i), anchor_sk(i).public_key().clone())?;
            }
            for i in 0..CLAIMS {
                r.record_pending_pair(
                    claim_static(i),
                    Some(claim_sk(i).public_key().clone()),
                    "Claim".into(),
                    "cli".into(),
                    "sas".into(),
                )?;
            }
            Ok(())
        })
        .unwrap();
}

fn issuer_key(ix: usize) -> HybridSigningPublicKey {
    if ix < PEERS {
        peer_sk(ix).public_key().clone()
    } else if ix < PEERS + ANCHORS {
        anchor_sk(ix - PEERS).public_key().clone()
    } else {
        local_identity().signing_key().public_key().clone()
    }
}

fn issuer_id(ix: usize) -> String {
    if ix < PEERS {
        peer_label(ix)
    } else if ix < PEERS + ANCHORS {
        anchor_label(ix - PEERS)
    } else {
        "local-host".to_owned()
    }
}

/// The reference model of the notice a `Revoked` entry ends with (`spec/pairing-v1.md`
/// Section 5.1), from the entry on disk and in memory before the fold alone.
fn expected_notice(disk: Option<&RosterEntry>, memory: Option<&RosterEntry>) -> Option<u64> {
    let memory_revoked = memory.filter(|m| m.state == PeerState::Revoked);
    match disk {
        Some(d) if d.state == PeerState::Revoked => {
            let kept = d.refusal_notice().map(|n| n.until_unix());
            if memory_revoked.is_some_and(|m| m.refusal_notice().is_none()) {
                None
            } else {
                kept
            }
        }
        Some(_) => memory_revoked
            .and_then(|m| m.refusal_notice())
            .map(|n| n.until_unix()),
        None => None,
    }
}

fn ed_bytes(key: &HybridSigningPublicKey) -> [u8; 32] {
    *key.ed25519_bytes()
}

/// Checks `result` against the invariants of Section 2, given the roster on disk (`disk`) and
/// in memory (`memory`) before the operation that produced it.
fn check(ctx: &str, disk: &Roster, memory: &Roster, result: &Roster) {
    let sides = [("disk", disk), ("memory", memory)];
    // INV-1 and INV-2: nothing revoked is lost.
    for (side, roster) in sides {
        for (key, entry) in roster.entries() {
            if entry.state != PeerState::Revoked {
                continue;
            }
            assert_eq!(
                result.get(key).map(|e| e.state),
                Some(PeerState::Revoked),
                "{ctx}: {key} revoked in {side}"
            );
            assert!(
                is_revoked(result, &entry.static_pub),
                "{ctx}: static key of {key} revoked in {side}"
            );
            if let Some(sig) = &entry.signing_pub {
                for (other, e) in result.entries() {
                    if e.signing_pub
                        .as_ref()
                        .is_some_and(|s| ed_bytes(s) == ed_bytes(sig))
                    {
                        assert_eq!(
                            e.state,
                            PeerState::Revoked,
                            "{ctx}: {other} shares the signing identity of {key} revoked in {side}"
                        );
                    }
                }
            }
        }
        for (id, anchor) in roster.trust_anchors() {
            if anchor.state != AnchorState::Revoked {
                continue;
            }
            assert_eq!(
                result.trust_anchor(id).map(|a| a.state),
                Some(AnchorState::Revoked),
                "{ctx}: anchor {id} revoked in {side}"
            );
            for (other, a) in result.trust_anchors() {
                if ed_bytes(&a.signing_pub) == ed_bytes(&anchor.signing_pub) {
                    assert_eq!(
                        a.state,
                        AnchorState::Revoked,
                        "{ctx}: anchor {other} shares the key of {id} revoked in {side}"
                    );
                }
            }
            for (other, e) in result.entries() {
                if e.signing_pub
                    .as_ref()
                    .is_some_and(|s| ed_bytes(s) == ed_bytes(&anchor.signing_pub))
                {
                    assert_eq!(
                        e.state,
                        PeerState::Revoked,
                        "{ctx}: {other} shares the key of anchor {id} revoked in {side}"
                    );
                }
            }
        }
    }
    for (issuer, crl) in disk
        .entries()
        .map(|(id, _)| id)
        .chain(disk.trust_anchors().map(|(id, _)| id))
        .chain(std::iter::once(&"local-host".to_owned()))
        .filter_map(|id| disk.crl(id).map(|c| (id, c)))
    {
        assert!(
            result.crl(issuer).is_some_and(|c| c.seq >= crl.seq),
            "{ctx}: the CRL of {issuer} never goes backwards"
        );
    }

    // INV-3: no non-revocation state crosses.
    for (key, entry) in result.entries() {
        match disk.get(key) {
            Some(d) if entry.state != PeerState::Revoked => assert_eq!(
                serde_json::to_vec(entry).unwrap(),
                serde_json::to_vec(d).unwrap(),
                "{ctx}: {key} is not a revocation and keeps the disk record"
            ),
            None => assert_eq!(
                entry.state,
                PeerState::Revoked,
                "{ctx}: only a revoked record is inserted ({key})"
            ),
            _ => {}
        }
        if entry.state == PeerState::Revoked && disk.get(key).is_none() {
            assert!(
                entry.routes.is_empty()
                    && entry.relay_hints.is_empty()
                    && entry.grants.is_empty()
                    && entry.v2_secrets.is_none()
                    && entry.route_meta.is_none(),
                "{ctx}: the inserted {key} carries nothing but its keys"
            );
        }
    }
    let local_routes = |r: &Roster| r.local_routes().map(|s| (s.seq(), *s.digest()));
    assert_eq!(
        local_routes(result),
        local_routes(disk),
        "{ctx}: local routes come from disk"
    );
    assert!(
        result.pending_hosts().count() <= disk.pending_hosts().count(),
        "{ctx}: a claim is only ever dropped"
    );

    // INV-4: the notice of each revoked entry follows the reference model.
    for (key, entry) in result.entries() {
        if entry.state != PeerState::Revoked {
            continue;
        }
        assert_eq!(
            entry.refusal_notice().map(|n| n.until_unix()),
            expected_notice(disk.get(key), memory.get(key)),
            "{ctx}: notice of {key}"
        );
    }
}

fn run_seed(seed: u64) {
    let fx = fixtures();
    let dir = tempdir().unwrap();
    let store = store_in(dir.path());
    seed_disk(&store);
    let other = StateStore::open_or_create(dir.path()).unwrap();
    let access = access_with_signer(&store);
    let local = local_identity();
    let local_pub = local.signing_key().public_key().clone();
    let mut rng = SplitMix64(seed);
    let mut crl_seq = [0usize; PEERS + ANCHORS + 1];
    let mut log = Vec::new();

    let sync = |op: usize, ctx: &str| {
        let disk = other.load_roster().unwrap();
        let memory = lock(access.roster()).clone();
        match op {
            0 => {
                let loaded = access.load().unwrap();
                check(ctx, &disk, &memory, &loaded);
                assert_eq!(
                    serde_json::to_vec(&other.load_roster().unwrap()).unwrap(),
                    serde_json::to_vec(&disk).unwrap(),
                    "{ctx}: load never writes"
                );
            }
            1 => {
                access.update(|_| Ok(())).unwrap();
                check(ctx, &disk, &memory, &other.load_roster().unwrap());
                check(ctx, &disk, &memory, &lock(access.roster()));
            }
            2 => {
                access.update_if_changed(|_| Ok(((), false))).unwrap();
                check(ctx, &disk, &memory, &other.load_roster().unwrap());
            }
            3 => {
                let before = serde_json::to_vec(&disk).unwrap();
                access.reload().unwrap();
                check(ctx, &disk, &memory, &lock(access.roster()));
                assert_eq!(
                    serde_json::to_vec(&other.load_roster().unwrap()).unwrap(),
                    before,
                    "{ctx}: reload never writes"
                );
            }
            _ => {
                access.commit_held_revocations().unwrap();
                check(ctx, &disk, &memory, &other.load_roster().unwrap());
                check(ctx, &disk, &memory, &lock(access.roster()));
            }
        }
    };

    let ops = 1 + rng.below(16);
    for step in 0..ops {
        let ctx = format!("seed {seed} step {step} after {log:?}");
        let choice = rng.below(19);
        let (p, a, c) = (rng.below(PEERS), rng.below(ANCHORS), rng.below(CLAIMS));
        let notify = rng.below(2) == 0;
        let issuer_ix = rng.below(PEERS + ANCHORS + 1);
        log.push(choice);
        match choice {
            0 => {
                let _ = lock(access.roster()).revoke_peer(&peer_label(p));
            }
            1 => {
                let _ = lock(access.roster()).revoke_peer_at(&peer_label(p), true, now_unix());
            }
            2 => {
                let [r0, r1] = fx.rotations[p].clone();
                let _ = lock(access.roster()).apply_verified_rotation(
                    &peer_label(p),
                    &[r0, r1],
                    &fresh_static(2 * p),
                    fresh_sk(2 * p).public_key(),
                );
            }
            3 => {
                let _ = lock(access.roster()).revoke_pending_host(&device_id(&claim_static(c)));
            }
            4 => {
                let _ = lock(access.roster()).revoke_trust_anchor(&anchor_label(a));
            }
            5 | 6 | 10 => {
                crl_seq[issuer_ix] =
                    (crl_seq[issuer_ix] + 1).min(usize::try_from(CRL_SEQS).unwrap());
                let list = fx.crls[issuer_ix][crl_seq[issuer_ix] - 1][p].clone();
                let id = issuer_id(issuer_ix);
                let key = issuer_key(issuer_ix);
                if choice == 10 {
                    let _ = other.update_roster(|r| {
                        let _ = r.ingest_crl(list, &id, &key);
                        Ok(())
                    });
                } else if choice == 6 && issuer_ix == PEERS + ANCHORS {
                    let _ = lock(access.roster()).ingest_crl_at(list, &id, &key, true, now_unix());
                } else {
                    let _ = lock(access.roster()).ingest_crl(list, &id, &key);
                }
            }
            7 => {
                let _ = other.update_roster(|r| {
                    let _ = r.revoke_peer_at(&peer_label(p), notify, now_unix());
                    Ok(())
                });
            }
            8 => {
                let _ = other.update_roster(|r| {
                    let _ = r.revoke_trust_anchor(&anchor_label(a));
                    Ok(())
                });
            }
            9 => {
                let _ = other.update_roster(|r| {
                    let _ = r.clear_refusal_notice(&peer_label(p));
                    Ok(())
                });
            }
            11 => {
                let _ = other.update_roster(|r| {
                    let _ = r.set_routes(
                        &peer_label(p),
                        vec![OperatorEndpoint {
                            hint: format!("direct:127.0.0.1:{}", 7000 + step),
                            relay_key: None,
                        }],
                    );
                    Ok(())
                });
            }
            12 => {
                let [r0, _] = fx.rotations[p].clone();
                let _ = other.update_roster(|r| {
                    let _ = r.apply_verified_rotation(
                        &peer_label(p),
                        &[r0],
                        &fresh_static(2 * p),
                        fresh_sk(2 * p).public_key(),
                    );
                    Ok(())
                });
            }
            13 => {
                let _ = other.update_roster(|r| {
                    let _ = r.insert_pinned_host(
                        device_id(&claim_static(c)),
                        "Replaced".into(),
                        fresh_static(8 + c),
                        Some(fresh_sk(8 + c).public_key().clone()),
                        0,
                        vec![],
                    );
                    Ok(())
                });
            }
            n => sync(n - 14, &ctx),
        }
    }

    // Commit what is left, then a fresh load after a restart sees all of it.
    let disk = other.load_roster().unwrap();
    let memory = lock(access.roster()).clone();
    let ctx = format!("seed {seed} final after {log:?}");
    access.commit_held_revocations().unwrap();
    check(&ctx, &disk, &memory, &other.load_roster().unwrap());
    let restarted =
        RosterAccess::from_store(Arc::new(StateStore::open_or_create(dir.path()).unwrap()))
            .unwrap()
            .with_local_signer(local.host_id(), local_pub);
    check(&ctx, &disk, &memory, &restarted.load().unwrap());

    // INV-5: a second commit is quiet.
    let before = stamp(&other);
    assert!(
        !access.commit_held_revocations().unwrap(),
        "{ctx}: a second commit has nothing new"
    );
    assert_eq!(stamp(&other), before, "{ctx}: and leaves the stamp alone");
}

#[test]
fn persist_reload_round_trip_never_loses_revocations() {
    const SEEDS: u64 = 512;
    const THREADS: u64 = 8;
    let _ = fixtures();
    // Signature checks dominate a debug build; spread the seeds over threads.
    let failures: BTreeMap<u64, String> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|worker| {
                scope.spawn(move || {
                    (worker..SEEDS)
                        .step_by(usize::try_from(THREADS).unwrap())
                        .filter_map(|seed| {
                            std::panic::catch_unwind(|| run_seed(seed)).err().map(|e| {
                                let text = e
                                    .downcast_ref::<String>()
                                    .cloned()
                                    .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                                    .unwrap_or_default();
                                (seed, text)
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect()
    });
    assert!(
        failures.is_empty(),
        "seeds failed: {:?}\nfirst: {:?}",
        failures.keys().collect::<Vec<_>>(),
        failures.iter().next()
    );
}
