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

    let lib_path = base.join("banderwagon");
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=banderwagon");
    println!("cargo:rustc-link-lib=static=banderwagon_cpu");
    // The c-abi shim was compiled with LUX_CRYPTO_HAS_METAL on this machine
    // so it references the Metal driver symbols. The driver returns NOTIMPL
    // and we transparently fall back to CPU. Link the metal stub regardless
    // so the symbols resolve.
    if cfg!(target_os = "macos") {
        let metal_lib = lib_path.join("libbanderwagon_metal.a");
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
