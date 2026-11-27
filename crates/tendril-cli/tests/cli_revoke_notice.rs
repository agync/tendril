//! `tendril revoke` records a refusal notice per the roster's refusal policy, and
//! `--no-notify` revokes silently (`spec/pairing-v1.md` Section 5.1).

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::TempDir;
use tendril_core::RefusalReason;
use tendril_core::crypto::StaticKeypair;
use tendril_core::roster::{PeerState, RefusalPolicy, Roster, V2PeerSecrets};
use tendril_runtime::StateStore;

fn run_tendril(state_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tendril"))
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("run tendril bin")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Adds an `Active` v2 peer built from `seed` and returns its `device_id` and static key.
fn peer(roster: &mut Roster, seed: u8) -> (String, [u8; 32]) {
    let static_pub = *StaticKeypair::from_scalar([seed; 32]).public_bytes();
    let id = tendril_core::crypto::device_id(&static_pub);
    roster
        .record_pending_pair(
            static_pub,
            None,
            "Phone".into(),
            "phone".into(),
            "1234".into(),
        )
        .expect("pending");
    roster.confirm_peer(&id, Some("1234")).expect("confirm");
    roster
        .upgrade_peer_to_v2(&id, V2PeerSecrets::new([seed; 32], [seed ^ 0xff; 32]))
        .expect("v2");
    (id, static_pub)
}

fn notice(roster: &Roster, static_pub: &[u8; 32]) -> Option<RefusalReason> {
    roster.refusal_for_static(static_pub, now())
}

#[test]
fn revoke_records_a_notice_unless_told_not_to() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let (loud, loud_key, quiet, quiet_key) = store
        .update_roster(|roster| {
            let (loud, loud_key) = peer(roster, 0x41);
            let (quiet, quiet_key) = peer(roster, 0x51);
            Ok((loud, loud_key, quiet, quiet_key))
        })
        .expect("seed");

    let out = run_tendril(dir.path(), &["revoke", &loud]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json["revoked"], loud);
    assert_eq!(json["notice"], true);

    let out = run_tendril(dir.path(), &["revoke", "--no-notify", &quiet]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json["revoked"], quiet);
    assert_eq!(json["notice"], false);

    let roster = store.load_roster().expect("roster");
    assert_eq!(roster.get(&loud).expect("peer").state, PeerState::Revoked);
    assert_eq!(roster.get(&quiet).expect("peer").state, PeerState::Revoked);
    assert_eq!(notice(&roster, &loud_key), Some(RefusalReason::Revoked));
    assert_eq!(notice(&roster, &quiet_key), None);
}

#[test]
fn revoke_follows_the_roster_policy_ttl() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let (id, key) = store
        .update_roster(|roster| {
            roster.set_refusal_policy(RefusalPolicy {
                pending: true,
                revoked_notice_ttl_secs: 0,
            });
            Ok(peer(roster, 0x61))
        })
        .expect("seed");
    let out = run_tendril(dir.path(), &["revoke", &id]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json["notice"], false, "a zero TTL records no notice");
    assert_eq!(notice(&store.load_roster().expect("roster"), &key), None);
}

fn json_stdout(out: &std::process::Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json")
}

#[test]
fn refusal_policy_prints_the_default_without_flags() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let json = json_stdout(&run_tendril(dir.path(), &["refusal-policy"]));
    assert_eq!(json["pending"], true);
    assert_eq!(json["revoked_notice_ttl_secs"], 2_592_000);
}

#[test]
fn refusal_policy_flags_set_and_persist_the_policy() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let store = StateStore::open_or_create(dir.path()).expect("store");

    let json = json_stdout(&run_tendril(
        dir.path(),
        &["refusal-policy", "--pending", "false"],
    ));
    assert_eq!(json["pending"], false);
    assert_eq!(json["revoked_notice_ttl_secs"], 2_592_000, "ttl untouched");

    let json = json_stdout(&run_tendril(
        dir.path(),
        &["refusal-policy", "--revoked-ttl-secs", "60"],
    ));
    assert_eq!(json["pending"], false, "pending untouched");
    assert_eq!(json["revoked_notice_ttl_secs"], 60);

    let policy = store.load_roster().expect("roster").refusal_policy();
    assert_eq!(
        policy,
        RefusalPolicy {
            pending: false,
            revoked_notice_ttl_secs: 60,
        }
    );
    let json = json_stdout(&run_tendril(dir.path(), &["refusal-policy"]));
    assert_eq!(json["pending"], false);
    assert_eq!(json["revoked_notice_ttl_secs"], 60);
}

#[test]
fn refusal_policy_rejects_a_non_boolean_pending() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let out = run_tendril(dir.path(), &["refusal-policy", "--pending", "maybe"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains("--pending"),
        "{stderr}"
    );
}

#[test]
fn clear_refusal_notice_drops_the_notice_and_keeps_the_peer_revoked() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let (id, key) = store
        .update_roster(|roster| Ok(peer(roster, 0x71)))
        .expect("seed");
    assert!(run_tendril(dir.path(), &["revoke", &id]).status.success());
    assert_eq!(
        notice(&store.load_roster().expect("roster"), &key),
        Some(RefusalReason::Revoked)
    );

    let json = json_stdout(&run_tendril(dir.path(), &["clear-refusal-notice", &id]));
    assert_eq!(json["cleared"], id);

    let roster = store.load_roster().expect("roster");
    assert_eq!(roster.get(&id).expect("peer").state, PeerState::Revoked);
    assert_eq!(notice(&roster, &key), None);
}

#[test]
fn clear_refusal_notice_fails_for_an_unknown_peer() {
    let dir = TempDir::new().expect("dir");
    assert!(run_tendril(dir.path(), &["init"]).status.success());
    let out = run_tendril(dir.path(), &["clear-refusal-notice", "no-such-peer"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("PeerNotFound") && stderr.contains("no-such-peer"),
        "{stderr}"
    );
}
