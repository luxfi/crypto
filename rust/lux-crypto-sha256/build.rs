// Build script for lux-crypto-sha256.
//
// Discovers `sha256/libsha256.a` produced by `luxcpp/crypto/sha256` and emits
// the link directives. Resolution order:
//   1. CRYPTO_DIR        -> $CRYPTO_DIR/lib/sha256/libsha256.a
//   2. CRYPTO_BUILD_DIR  -> $CRYPTO_BUILD_DIR/sha256/libsha256.a
//   3. Default to ../../../../luxcpp/crypto/build-cto/sha256/

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
    // libsha256.a holds the C-ABI shim; libsha256_cpu.a holds the C++ body it
    // delegates into (namespaced cevm::crypto::sha256). Both are needed.
    println!("cargo:rustc-link-lib=static=sha256");
    println!("cargo:rustc-link-lib=static=sha256_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
