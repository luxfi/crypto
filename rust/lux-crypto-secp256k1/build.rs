// Build script for lux-crypto-secp256k1.
//
// Discovers `secp256k1/libsecp256k1_cpu.a` produced by `luxcpp/crypto` and
// emits link directives. Resolution order (first hit wins):
//   1. CRYPTO_DIR        -> $CRYPTO_DIR/lib/secp256k1/libsecp256k1_cpu.a
//   2. CRYPTO_BUILD_DIR  -> $CRYPTO_BUILD_DIR/secp256k1/libsecp256k1_cpu.a
//   3. Default to ../../../../luxcpp/crypto/build-canonical/secp256k1/

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
            .join("build-canonical")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    let lib_path = base.join("secp256k1");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=secp256k1_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
