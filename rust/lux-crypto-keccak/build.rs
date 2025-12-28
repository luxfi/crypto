// Build script for lux-crypto-keccak.
//
// Discovers `keccak/libkeccak_cpu.a` produced by `luxcpp/crypto` and emits the
// link directives. Resolution order (first hit wins):
//   1. CRYPTO_DIR        - install prefix; archive at $CRYPTO_DIR/lib/keccak/libkeccak_cpu.a
//   2. CRYPTO_BUILD_DIR  - cmake build directory; archive at $CRYPTO_BUILD_DIR/keccak/libkeccak_cpu.a
//   3. Default fallback to ../../../../luxcpp/crypto/build-canonical
//
// We link the C++ runtime (libc++ on macOS, libstdc++ elsewhere) because the
// archive contains C++ object code from the canonical implementation.

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

    let lib_path = base.join("keccak");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=keccak");
    println!("cargo:rustc-link-lib=static=keccak_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
