fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "android" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libtendril_ffi.so");
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,max-page-size=16384");
    } else if target_os == "linux" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libtendril_ffi.so");
    }
}
