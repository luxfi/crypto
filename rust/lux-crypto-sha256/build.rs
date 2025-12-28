// Build script for lux-crypto-sha256.
//
// The C-ABI extern "C" symbol `sha256` lives in `libsha256.a` (the shim
// archive that contains only `c_sha256.cpp.o`). The CPU implementation body
// lives in `libsha256_cpu.a`. We link both static archives in the order
// shim-then-body so the linker picks up `_sha256` and resolves
// `cevm::crypto::sha256` from the body.

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
    // Order matters: shim first (has _sha256 extern "C"), body second.
    println!("cargo:rustc-link-lib=static=sha256");
    println!("cargo:rustc-link-lib=static=sha256_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
