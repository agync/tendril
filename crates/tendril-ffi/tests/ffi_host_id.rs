//! A tampered local identity never becomes an endpoint.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use serde_json::Value;
use tendril_ffi::{
    TENDRIL_OK, tendril_endpoint_export_identity_json, tendril_endpoint_free, tendril_endpoint_new,
    tendril_endpoint_new_from_state, tendril_endpoint_new_sealed, tendril_string_free,
};

fn cs(s: &str) -> CString {
    CString::new(s).expect("no interior NUL")
}

fn tampered_identity_json() -> String {
    let dir = tempfile::tempdir().expect("dir");
    let state = cs(dir.path().to_str().expect("path"));
    let ep = unsafe { tendril_endpoint_new(state.as_ptr(), cs("good-host").as_ptr()) };
    assert!(!ep.is_null());
    let mut out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(ep, &raw mut out) },
        TENDRIL_OK
    );
    let raw = unsafe { CStr::from_ptr(out) }
        .to_str()
        .expect("utf8")
        .to_owned();
    unsafe { tendril_string_free(out) };
    unsafe { tendril_endpoint_free(ep) };
    let mut doc: Value = serde_json::from_str(&raw).expect("json");
    doc["host_id"] = "has#hash".into();
    doc.to_string()
}

#[test]
fn a_tampered_identity_never_becomes_an_endpoint() {
    let identity = tampered_identity_json();

    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("identity.json"), &identity).expect("write");
    #[cfg(unix)]
    std::fs::set_permissions(
        dir.path().join("identity.json"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");
    let state = cs(dir.path().to_str().expect("path"));
    assert!(unsafe { tendril_endpoint_new(state.as_ptr(), ptr::null()) }.is_null());

    let id = cs(&identity);
    assert!(
        unsafe { tendril_endpoint_new_from_state(id.as_ptr(), ptr::null(), ptr::null()) }.is_null()
    );

    let sealed = tempfile::tempdir().expect("dir");
    let sealed_state = cs(sealed.path().to_str().expect("path"));
    assert!(
        unsafe {
            tendril_endpoint_new_sealed(
                sealed_state.as_ptr(),
                id.as_ptr(),
                ptr::null(),
                ptr::null(),
            )
        }
        .is_null()
    );

    for bad in ["has#hash", "x\u{7}y"] {
        let host = cs(bad);
        assert!(
            unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), host.as_ptr()) }
                .is_null(),
            "{bad:?}"
        );
    }
}
