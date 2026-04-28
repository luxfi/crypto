// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Build script for lux-crypto. Locates the luxcpp/crypto build outputs and
// emits cargo linker directives for every algorithm exposed by the crate.
//
// One compiled artifact per algorithm; we accept the `<alg>/lib<alg>_cpu.a`
// layout that `luxcpp/crypto/build-canonical/` produces by default.

use std::env;
use std::path::PathBuf;

/// Each first-party algorithm corresponds to:
///   - a build subdirectory `build-canonical/<dir>/`
///   - a static archive named `lib<lib>_cpu.a`
const ALGS: &[(&str, &str)] = &[
    ("secp256k1", "secp256k1"),
    ("mldsa",     "mldsa"),
    ("mlkem",     "mlkem"),
    ("slhdsa",    "slhdsa"),
    ("ed25519",   "ed25519"),
    ("keccak",    "keccak"),
];

fn main() {
    let crypto_dir = env::var("CRYPTO_DIR").ok();
    let build_dir = env::var("CRYPTO_BUILD_DIR").ok();

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let base: PathBuf = if let Some(d) = crypto_dir {
        PathBuf::from(d).join("lib")
    } else if let Some(d) = build_dir {
        PathBuf::from(d)
    } else {
        // Default: assume luxcpp/crypto is a sibling at ../../../../luxcpp/crypto.
        manifest_dir
            .join("..").join("..").join("..")
            .join("..").join("luxcpp").join("crypto")
            .join("build-canonical")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    for (subdir, lib) in ALGS {
        let lib_path = base.join(subdir);
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:rustc-link-lib=static={}_cpu", lib);
    }

    // C++ runtime
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
