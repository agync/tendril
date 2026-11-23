//! A peer paired with the human code flow can be added to a group with its signing key.

use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingInitiator, PairingManager,
    PairingPathKind, PairingResponder,
};
use tendril_core::roster::Roster;
use tendril_runtime::{StateStore, group_add_member, group_create};

const NOW_UNIX: u64 = 1_795_564_800;

fn writes(actions: &[PairAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let PairAction::WriteBytes(b) = a {
            out.extend_from_slice(b);
        }
    }
    out
}

/// Runs a sans-I/O v1 human pairing of `peer` into `roster` and returns the responder SAS.
fn code_pair(host: &EndpointIdentity, peer: &EndpointIdentity, roster: &mut Roster) -> String {
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let mut init = PairingInitiator::new(peer, "Laptop", "cli", &code, None, None).unwrap();
    let mut resp = PairingResponder::new(host, PairingPathKind::Remote, None).unwrap();
    let mut to_resp = writes(&init.start().unwrap());
    for _ in 0..4 {
        let acts = resp
            .feed_bytes(&to_resp, NOW_UNIX, &mut mgr, roster)
            .unwrap();
        for a in &acts {
            if let PairAction::Completed(outcome) = a {
                let PairOutcome::ResponderPending { pairing_sas, .. } = outcome else {
                    panic!("expected ResponderPending, got {outcome:?}");
                };
                return pairing_sas.clone();
            }
        }
        to_resp = writes(&init.feed_bytes(&writes(&acts)).unwrap());
    }
    panic!("pairing never completed");
}

#[test]
fn code_paired_peer_is_added_with_its_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open_or_create(dir.path()).unwrap();
    let a = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x71; 32]),
        SigningKeypair::from_seed([0x72; 32]),
    );
    let b = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x73; 32]),
        SigningKeypair::from_seed([0x74; 32]),
    );

    let sas = store.update_roster(|r| Ok(code_pair(&a, &b, r))).unwrap();
    store
        .update_roster(|r| {
            r.confirm_peer(&b.device_id(), Some(&sas))?;
            Ok(())
        })
        .unwrap();

    let gid = group_create(&store, &a, "team", 2, vec![])
        .unwrap()
        .group_id;
    let m = group_add_member(&store, &a, &gid, &b.device_id(), vec![], vec![]).unwrap();
    let member = m
        .members
        .iter()
        .find(|x| x.device_id == b.device_id())
        .unwrap();
    assert_eq!(
        member.signing_pub_hash,
        b64url_encode(&b.signing_key().public_key().sha256_hash())
    );
}
