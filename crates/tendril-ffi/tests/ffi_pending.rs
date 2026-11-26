//! Listing, removing and revoking unconfirmed host claims through the C ABI.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use serde_json::Value;
use tendril_core::crypto::{SigningKeypair, StaticKeypair, device_id};
use tendril_core::roster::{PeerState, Roster};
use tendril_ffi::{
    TENDRIL_ERR_INTERNAL, TENDRIL_ERR_INVALID_ARG, TENDRIL_ERR_NOT_FOUND, TENDRIL_OK,
    TendrilEndpoint, tendril_endpoint_free, tendril_endpoint_new, tendril_endpoint_pending_hosts,
    tendril_endpoint_remove_pending_host, tendril_endpoint_revoke_pending_host,
    tendril_string_free,
};
use tendril_runtime::StateStore;

fn cs(s: &str) -> CString {
    CString::new(s).expect("no interior NUL")
}

struct Ep(*mut TendrilEndpoint);

impl Drop for Ep {
    fn drop(&mut self) {
        unsafe { tendril_endpoint_free(self.0) };
    }
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

fn listed(ep: &Ep) -> Vec<Value> {
    let mut out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_pending_hosts(ep.0, &raw mut out) },
        TENDRIL_OK
    );
    assert!(!out.is_null());
    let text = unsafe { CStr::from_ptr(out) }
        .to_str()
        .expect("utf8")
        .to_owned();
    unsafe { tendril_string_free(out) };
    serde_json::from_str::<Value>(&text)
        .expect("json")
        .as_array()
        .expect("array")
        .clone()
}

#[test]
fn pending_hosts_list_remove_and_revoke_by_device_id() {
    let dir = tempfile::tempdir().expect("dir");
    let (genuine, decoy) = {
        let store = StateStore::open_or_create(dir.path()).expect("store");
        store
            .update_roster(|roster| {
                let genuine = claim(roster, "studio", 0x41);
                let decoy = claim(roster, "studio", 0x51);
                claim(roster, "other", 0x61);
                Ok((genuine, decoy))
            })
            .expect("seed claims")
    };
    let state = cs(dir.path().to_str().expect("path"));
    let ep = Ep(unsafe { tendril_endpoint_new(state.as_ptr(), ptr::null()) });
    assert!(!ep.0.is_null());

    let claims = listed(&ep);
    assert_eq!(claims.len(), 3, "{claims:?}");
    assert_eq!(claims[0]["host_id"], "studio");
    assert_eq!(claims[0]["device_id"], genuine);
    assert_eq!(claims[0]["pairing_sas"], "123456");

    // A claimed host_id is not an authenticated id: revoking by it finds nothing.
    let label = cs("other");
    assert_eq!(
        unsafe { tendril_endpoint_revoke_pending_host(ep.0, label.as_ptr()) },
        TENDRIL_ERR_NOT_FOUND
    );
    assert_eq!(listed(&ep).len(), 3);

    let decoy_id = cs(&decoy);
    assert_eq!(
        unsafe { tendril_endpoint_revoke_pending_host(ep.0, decoy_id.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(listed(&ep).len(), 2);
    let roster = StateStore::open_or_create(dir.path())
        .expect("store")
        .load_roster()
        .expect("roster");
    let decoy_key = *StaticKeypair::from_scalar([0x51; 32]).public_bytes();
    assert!(
        roster
            .entries()
            .any(|(_, e)| e.static_pub == decoy_key && e.state == PeerState::Revoked),
        "the claimed keys are revoked on disk"
    );

    let studio = cs("studio");
    assert_eq!(
        unsafe { tendril_endpoint_remove_pending_host(ep.0, studio.as_ptr()) },
        TENDRIL_OK
    );
    let left = listed(&ep);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["host_id"], "other");
    assert_eq!(
        unsafe { tendril_endpoint_remove_pending_host(ep.0, studio.as_ptr()) },
        TENDRIL_ERR_NOT_FOUND
    );
}

#[test]
fn removing_claims_never_touches_roster_entries() {
    let dir = tempfile::tempdir().expect("dir");
    let inbound_key = *StaticKeypair::from_scalar([0x71; 32]).public_bytes();
    let inbound = device_id(&inbound_key);
    {
        let store = StateStore::open_or_create(dir.path()).expect("store");
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
    }
    let state = cs(dir.path().to_str().expect("path"));
    let ep = Ep(unsafe { tendril_endpoint_new(state.as_ptr(), ptr::null()) });
    assert!(!ep.0.is_null());

    let id = cs(&inbound);
    assert_eq!(
        unsafe { tendril_endpoint_remove_pending_host(ep.0, id.as_ptr()) },
        TENDRIL_OK
    );
    assert!(listed(&ep).is_empty());
    let roster = StateStore::open_or_create(dir.path())
        .expect("store")
        .load_roster()
        .expect("roster");
    assert_eq!(
        roster.get(&inbound).map(|e| e.state),
        Some(PeerState::Pending),
        "the inbound device survives"
    );

    // An entry is no claim: NOT_FOUND, and untouched.
    let act = cs("act");
    assert_eq!(
        unsafe { tendril_endpoint_remove_pending_host(ep.0, act.as_ptr()) },
        TENDRIL_ERR_NOT_FOUND
    );
    assert_eq!(
        StateStore::open_or_create(dir.path())
            .expect("store")
            .load_roster()
            .expect("roster")
            .get("act")
            .map(|e| e.state),
        Some(PeerState::Active)
    );
}

#[test]
fn pending_host_calls_reject_bad_arguments() {
    let dir = tempfile::tempdir().expect("dir");
    let state = cs(dir.path().to_str().expect("path"));
    let ep = Ep(unsafe { tendril_endpoint_new(state.as_ptr(), ptr::null()) });
    let mut out: *mut c_char = ptr::NonNull::<c_char>::dangling().as_ptr();
    assert_eq!(
        unsafe { tendril_endpoint_pending_hosts(ptr::null_mut(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(out.is_null(), "out_json is cleared on every error path");
    assert_eq!(
        unsafe { tendril_endpoint_pending_hosts(ep.0, ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );

    let invalid_utf8 = CString::new(vec![0xff, 0xfe]).expect("no NUL");
    for rc in [
        unsafe { tendril_endpoint_remove_pending_host(ep.0, invalid_utf8.as_ptr()) },
        unsafe { tendril_endpoint_revoke_pending_host(ep.0, invalid_utf8.as_ptr()) },
        unsafe { tendril_endpoint_remove_pending_host(ep.0, ptr::null()) },
        unsafe { tendril_endpoint_revoke_pending_host(ep.0, ptr::null()) },
        unsafe { tendril_endpoint_remove_pending_host(ptr::null_mut(), invalid_utf8.as_ptr()) },
        unsafe { tendril_endpoint_revoke_pending_host(ptr::null_mut(), invalid_utf8.as_ptr()) },
    ] {
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
    }

    // A roster the store cannot read is an internal error, not a protocol one.
    std::fs::write(dir.path().join("roster.json"), b"not a roster").expect("corrupt");
    let mut out: *mut c_char = ptr::NonNull::<c_char>::dangling().as_ptr();
    assert_eq!(
        unsafe { tendril_endpoint_pending_hosts(ep.0, &raw mut out) },
        TENDRIL_ERR_INTERNAL
    );
    assert!(out.is_null());
}
