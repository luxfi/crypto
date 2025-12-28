// Build script for lux-crypto-poseidon.
//
// Discovers the static archives produced by `luxcpp/crypto/poseidon` and emits
// the link directives. Resolution order (first hit wins):
//   1. CRYPTO_DIR        - install prefix; archives at $CRYPTO_DIR/lib/poseidon/
//   2. CRYPTO_BUILD_DIR  - cmake build directory; archives at $CRYPTO_BUILD_DIR/poseidon/
//   3. Default fallback to ../../../../luxcpp/crypto/build-cto
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
            .join("build-cto")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    let lib_path = base.join("poseidon");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    // The umbrella `libposeidon.a` carries the C-ABI shim; the CPU body lives
    // in `libposeidon_cpu.a`. Both are required for symbol resolution.
    println!("cargo:rustc-link-lib=static=poseidon");
    println!("cargo:rustc-link-lib=static=poseidon_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
