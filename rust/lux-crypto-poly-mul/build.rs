use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let base: PathBuf = if let Ok(d) = env::var("CRYPTO_DIR") {
        PathBuf::from(d).join("lib")
    } else if let Ok(d) = env::var("CRYPTO_BUILD_DIR") {
        PathBuf::from(d)
    } else {
        manifest_dir.join("..").join("..").join("..").join("..")
            .join("luxcpp").join("crypto").join("build-cto")
    };
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");
    // poly_mul body is exported from libntt.a (lux::crypto::ntt namespace +
    // top-level _poly_mul C-ABI shim). libpoly_mul.a is empty per the
    // CMake layout; we still link it so the search path is honored.
    let ntt_path = base.join("ntt");
    println!("cargo:rustc-link-search=native={}", ntt_path.display());
    println!("cargo:rustc-link-lib=static=ntt");
    println!("cargo:rustc-link-lib=static=ntt_cpu");
    if cfg!(target_os = "macos") { println!("cargo:rustc-link-lib=c++"); } else { println!("cargo:rustc-link-lib=stdc++"); }
}
