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

    let kzg_path = base.join("kzg");
    let sha256_path = base.join("sha256");
    let blst_path = base.join("blst-oracle/src/blst_oracle");
    println!("cargo:rustc-link-search=native={}", kzg_path.display());
    println!("cargo:rustc-link-search=native={}", sha256_path.display());
    println!("cargo:rustc-link-search=native={}", blst_path.display());
    println!("cargo:rustc-link-lib=static=kzg");
    println!("cargo:rustc-link-lib=static=kzg_cpu");
    println!("cargo:rustc-link-lib=static=sha256_cpu");
    println!("cargo:rustc-link-lib=static=blst");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
