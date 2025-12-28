// Build script for lux-crypto-sha256.
//
// Links statically against `libsha256.a` (the C-ABI shim) and `libsha256_cpu.a`
// (the canonical CPU body) produced by `luxcpp/crypto/sha256`.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let base: PathBuf = if let Ok(d) = env::var("CRYPTO_DIR") {
        PathBuf::from(d).join("lib")
    } else if let Ok(d) = env::var("CRYPTO_BUILD_DIR") {
        PathBuf::from(d)
    } else {
        manifest_dir
            .join("..")
            .join("..")
            .join("..")
            .join("..")
            .join("luxcpp")
            .join("crypto")
            .join("build-cto")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    let lib_path = base.join("sha256");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=sha256");
    println!("cargo:rustc-link-lib=static=sha256_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
