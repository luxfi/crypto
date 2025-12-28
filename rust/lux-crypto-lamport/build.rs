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

    // Lamport body links against the SHA-256 archive; link both sha256 and lamport.
    let lamport_path = base.join("lamport");
    let sha256_path = base.join("sha256");
    println!("cargo:rustc-link-search=native={}", lamport_path.display());
    println!("cargo:rustc-link-search=native={}", sha256_path.display());
    println!("cargo:rustc-link-lib=static=lamport");
    println!("cargo:rustc-link-lib=static=lamport_cpu");
    println!("cargo:rustc-link-lib=static=sha256_cpu");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
