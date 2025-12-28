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

    let verkle_path = base.join("verkle");
    let ipa_path = base.join("ipa");
    let banderwagon_path = base.join("banderwagon");
    println!("cargo:rustc-link-search=native={}", verkle_path.display());
    println!("cargo:rustc-link-search=native={}", ipa_path.display());
    println!("cargo:rustc-link-search=native={}", banderwagon_path.display());
    println!("cargo:rustc-link-lib=static=verkle");
    println!("cargo:rustc-link-lib=static=verkle_cpu");
    println!("cargo:rustc-link-lib=static=ipa_cpu");
    println!("cargo:rustc-link-lib=static=banderwagon_cpu");

    if cfg!(target_os = "macos") {
        let metal_lib = banderwagon_path.join("libbanderwagon_metal.a");
        if metal_lib.exists() {
            println!("cargo:rustc-link-lib=static=banderwagon_metal");
            println!("cargo:rustc-link-lib=framework=Metal");
            println!("cargo:rustc-link-lib=framework=Foundation");
        }
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
