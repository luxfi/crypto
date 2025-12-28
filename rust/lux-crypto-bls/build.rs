use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // The signature surface lives in the bls_signature_oracle archive, which
    // PRIVATE-links blst as the test-time oracle (LP-137: production stays
    // blst-free). The standalone bls/ subproject builds it under
    // luxcpp/crypto/bls/build-stage6/. Override via BLS_SIG_BUILD_DIR or
    // CRYPTO_BUILD_DIR in CI.
    let bls_build: PathBuf = if let Ok(d) = env::var("BLS_SIG_BUILD_DIR") {
        PathBuf::from(d)
    } else if let Ok(d) = env::var("CRYPTO_BUILD_DIR") {
        PathBuf::from(d).join("bls")
    } else {
        manifest_dir
            .join("..")
            .join("..")
            .join("..")
            .join("..")
            .join("luxcpp")
            .join("crypto")
            .join("bls")
            .join("build-stage6")
    };

    // blst is at the same canonical path that crypto/bls/CMakeLists.txt
    // uses (cevm/build/deps/src/blst).
    let blst_lib = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("luxcpp")
        .join("cevm")
        .join("build")
        .join("deps")
        .join("src")
        .join("blst");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=BLS_SIG_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");

    println!("cargo:rustc-link-search=native={}", bls_build.display());
    println!("cargo:rustc-link-lib=static=bls_signature_oracle");

    println!("cargo:rustc-link-search=native={}", blst_lib.display());
    println!("cargo:rustc-link-lib=static=blst");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
