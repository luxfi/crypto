// Build script for lux-crypto-kzg. Links `libkzg.a` and `libkzg_cpu.a` produced
// by `luxcpp/crypto/kzg`. The CPU body links blst privately for pairings.

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

    let lib_path = base.join("kzg");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=kzg");
    println!("cargo:rustc-link-lib=static=kzg_cpu");

    // KZG depends on blst (BLS12-381 pairings) and the SHA-256 unit.
    let blst = base.join("blst-oracle").join("src").join("blst_oracle");
    println!("cargo:rustc-link-search=native={}", blst.display());
    println!("cargo:rustc-link-lib=static=blst");
    let sha = base.join("sha256");
    println!("cargo:rustc-link-search=native={}", sha.display());
    println!("cargo:rustc-link-lib=static=sha256_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
