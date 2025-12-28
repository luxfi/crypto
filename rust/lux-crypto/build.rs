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

/// Algorithms the umbrella crate links. Each entry contributes both the
/// `<alg>` umbrella archive (c-abi shim) and `<alg>_cpu` body archive.
const ALGS: &[&str] = &[
    "secp256k1",
    "mldsa",
    "mlkem",
    "slhdsa",
    "keccak",
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
