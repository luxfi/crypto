// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Build script for lux-crypto-sys. Locates the luxcpp/crypto build output
// and emits cargo linker directives.

use std::env;
use std::path::PathBuf;

fn main() {
    let crypto_dir = env::var("LUX_CRYPTO_DIR").ok();
    let build_dir = env::var("LUX_CRYPTO_BUILD_DIR").ok();

    let lib_path: PathBuf = if let Some(d) = crypto_dir {
        PathBuf::from(d).join("lib")
    } else if let Some(d) = build_dir {
        PathBuf::from(d).join("secp256k1")
    } else {
        // Default: assume luxcpp/crypto is a sibling at ../../../luxcpp/crypto.
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("..").join("..").join("..")
            .join("..").join("luxcpp").join("crypto")
            .join("build-canonical").join("secp256k1")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=LUX_CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=LUX_CRYPTO_BUILD_DIR");

    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=secp256k1_cpu");

    // C++ runtime
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
