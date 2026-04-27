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

fn read_env_with_legacy(new_name: &str, legacy_name: &str) -> Option<String> {
    if let Ok(v) = env::var(new_name) {
        return Some(v);
    }
    if let Ok(v) = env::var(legacy_name) {
        println!("cargo:warning={legacy_name} is deprecated; use {new_name}");
        return Some(v);
    }
    None
}

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
    let crypto_dir = read_env_with_legacy("CRYPTO_DIR", "LUX_CRYPTO_DIR");
    let build_dir = read_env_with_legacy("CRYPTO_BUILD_DIR", "LUX_CRYPTO_BUILD_DIR");

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
    println!("cargo:rerun-if-env-changed=LUX_CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=LUX_CRYPTO_BUILD_DIR");

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
