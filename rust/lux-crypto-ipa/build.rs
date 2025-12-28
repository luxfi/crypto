// Build script for lux-crypto-ipa. Links the C-ABI archive (`libipa.a`) and
// CPU body archive (`libipa_cpu.a`) produced by `luxcpp/crypto/ipa`.

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

    let lib_path = base.join("ipa");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=ipa");
    println!("cargo:rustc-link-lib=static=ipa_cpu");

    // IPA depends on Banderwagon group + SHA-256 transcript hashing.
    let bw = base.join("banderwagon");
    println!("cargo:rustc-link-search=native={}", bw.display());
    println!("cargo:rustc-link-lib=static=banderwagon");
    println!("cargo:rustc-link-lib=static=banderwagon_cpu");
    let sha = base.join("sha256");
    println!("cargo:rustc-link-search=native={}", sha.display());
    println!("cargo:rustc-link-lib=static=sha256_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
