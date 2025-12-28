// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Build script for lux-crypto. Locates the luxcpp/crypto build outputs and
// emits cargo linker directives for every algorithm exposed by the crate.
//
// Each algorithm produces two static archives in the cmake build dir:
//   * <alg>/lib<alg>.a       -- C-ABI shim (extern "C" entry points)
//   * <alg>/lib<alg>_cpu.a   -- algorithm body (C++ implementation)
//
// Some bodies inline the c-abi shim into `lib<alg>_cpu.a`; others keep it
// separate. We link both per algorithm and let the linker resolve.

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
        // Default to build-cto to match the per-algorithm member crates
        // (lux-crypto-secp256k1, lux-crypto-keccak, etc.) which all default to
        // build-cto. build-cto contains brand-neutral C-ABI symbols (post the
        // 2026-04-26 rename) and all required archives. build-canonical is a
        // partial build dir that may have stale objects from before the rename
        // and does not contain banderwagon/sha256/ripemd160 archives.
        manifest_dir
            .join("..").join("..").join("..")
            .join("..").join("luxcpp").join("crypto")
            .join("build-cto")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    for alg in ALGS {
        let lib_path = base.join(alg);
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:rustc-link-lib=static={}", alg);
        println!("cargo:rustc-link-lib=static={}_cpu", alg);
    }

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
