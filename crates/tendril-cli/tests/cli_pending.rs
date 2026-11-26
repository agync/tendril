//! Listing, removing and revoking unconfirmed host claims from the CLI.

use std::process::Command;

use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair, device_id};
use tendril_core::roster::{PeerState, Roster};
use tendril_runtime::StateStore;

fn run_tendril(state_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tendril"))
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("run tendril bin")
}

fn json_out(out: &std::process::Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout json")
}

fn claim(roster: &mut Roster, label: &str, seed: u8) -> String {
    let static_pub = *StaticKeypair::from_scalar([seed; 32]).public_bytes();
    let signing = SigningKeypair::from_seed([seed.wrapping_add(1); 32])
        .public_key()
        .clone();
    roster
        .record_pending_host(
            label.to_owned(),
            "Studio".to_owned(),
            static_pub,
            signing,
            0,
            "123456".to_owned(),
            Vec::new(),
        )
        .expect("record claim");
    device_id(&static_pub)
}

#[test]
fn pending_list_remove_and_revoke_by_device_id() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let (genuine, decoy) = store
        .update_roster(|roster| {
            let genuine = claim(roster, "studio", 0x41);
            let decoy = claim(roster, "studio", 0x51);
            claim(roster, "other", 0x61);
            Ok((genuine, decoy))
        })
        .expect("seed claims");

    let listed = json_out(&run_tendril(dir.path(), &["pending", "list"]));
    let claims = listed["pending_hosts"].as_array().expect("claims");
    assert_eq!(claims.len(), 3, "{listed}");
    assert_eq!(claims[0]["host_id"], "studio");
    assert_eq!(claims[0]["device_id"], genuine);
    assert_eq!(claims[0]["pairing_sas"], "123456");

    let revoked = json_out(&run_tendril(dir.path(), &["pending", "revoke", &decoy]));
    assert_eq!(revoked["revoked_pending"], decoy);
    let left = json_out(&run_tendril(dir.path(), &["pending", "list"]));
    assert_eq!(left["pending_hosts"].as_array().expect("claims").len(), 2);
    let roster = store.load_roster().expect("roster");
    let decoy_key = *StaticKeypair::from_scalar([0x51; 32]).public_bytes();
    assert!(
        roster
            .entries()
            .any(|(_, e)| e.static_pub == decoy_key && e.state == PeerState::Revoked),
        "the claimed keys are revoked"
    );
    assert!(roster.get("studio").is_none(), "the label stays free");

    // A claimed host_id is not an authenticated id: revoking by it finds nothing.
    let by_label = run_tendril(dir.path(), &["pending", "revoke", "other"]);
    assert!(!by_label.status.success());
    assert_eq!(
        json_out(&run_tendril(dir.path(), &["pending", "list"]))["pending_hosts"]
            .as_array()
            .expect("claims")
            .len(),
        2
    );

    let removed = json_out(&run_tendril(dir.path(), &["pending", "remove", "studio"]));
    assert_eq!(removed["removed_pending"], "studio");
    let after = json_out(&run_tendril(dir.path(), &["pending", "list"]));
    let hosts: Vec<_> = after["pending_hosts"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| c["host_id"].as_str().expect("host_id").to_owned())
        .collect();
    assert_eq!(hosts, ["other"]);
    assert!(
        store.load_roster().expect("roster").get("studio").is_none(),
        "removing claims revokes nothing"
    );
}

#[test]
fn removing_claims_never_touches_roster_entries() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let inbound_key = *StaticKeypair::from_scalar([0x71; 32]).public_bytes();
    let inbound = device_id(&inbound_key);
    store
        .update_roster(|roster| {
            roster
                .record_pending_pair(
                    inbound_key,
                    Some(SigningKeypair::from_seed([0x72; 32]).public_key().clone()),
                    "Inbound".to_owned(),
                    "cli".to_owned(),
                    "654321".to_owned(),
                )
                .expect("inbound pending device");
            // A hostile host names the id of the real inbound device.
            claim(roster, &inbound, 0x41);
            let active_key = *StaticKeypair::from_scalar([0x75; 32]).public_bytes();
            let active_signing = SigningKeypair::from_seed([0x76; 32]).public_key().clone();
            roster
                .insert_pinned_host(
                    "act".to_owned(),
                    "Active".to_owned(),
                    active_key,
                    Some(active_signing),
                    0,
                    Vec::new(),
                )
                .expect("pin");
            Ok(())
        })
        .expect("seed");

    let removed = json_out(&run_tendril(dir.path(), &["pending", "remove", &inbound]));
    assert_eq!(removed["removed_pending"], inbound.as_str());
    let roster = store.load_roster().expect("roster");
    assert_eq!(roster.pending_hosts().count(), 0);
    assert_eq!(
        roster.get(&inbound).map(|e| e.state),
        Some(PeerState::Pending),
        "the inbound device survives"
    );

    // An entry is no claim: not found, and untouched.
    let out = run_tendril(dir.path(), &["pending", "remove", "act"]);
    assert!(!out.status.success());
    let roster = store.load_roster().expect("roster");
    assert_eq!(roster.get("act").map(|e| e.state), Some(PeerState::Active));
    assert!(roster.get(&inbound).is_some());
}
