// Build script for lux-crypto-poly-mul. The `poly_mul` C-ABI symbol lives in
// `libntt.a` (the NTT subsystem owns the symbol per luxcpp/crypto/poly_mul);
// we link it from there. The `libpoly_mul_cpu.a` archive carries the helper
// symbols specific to the negacyclic poly_mul body.

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
            .join("..").join("..").join("..").join("..")
            .join("luxcpp").join("crypto").join("build-cto")
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    // poly_mul body archive: helpers used by the negacyclic ring multiply.
    let pm = base.join("poly_mul");
    println!("cargo:rustc-link-search=native={}", pm.display());
    println!("cargo:rustc-link-lib=static=poly_mul_cpu");

    // The C-ABI symbol `poly_mul` itself is exported from the NTT subsystem.
    let ntt = base.join("ntt");
    println!("cargo:rustc-link-search=native={}", ntt.display());
    println!("cargo:rustc-link-lib=static=ntt");
    println!("cargo:rustc-link-lib=static=ntt_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
