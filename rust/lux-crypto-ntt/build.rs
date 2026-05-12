use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let base: PathBuf = if let Ok(d) = env::var("CRYPTO_DIR") {
        PathBuf::from(d).join("lib")
    } else if let Ok(d) = env::var("CRYPTO_BUILD_DIR") {
        PathBuf::from(d)
    } else {
        manifest_dir.join("..").join("..").join("..").join("..")
            .join("luxcpp").join("crypto").join("build")
    };
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");
    // `_poly_mul` is exported from libpoly_mul, not libntt — both ship under
    // their own subdir in the luxcpp/crypto build tree.
    let ntt_path = base.join("ntt");
    let poly_mul_path = base.join("poly_mul");
    println!("cargo:rustc-link-search=native={}", ntt_path.display());
    println!("cargo:rustc-link-search=native={}", poly_mul_path.display());
    println!("cargo:rustc-link-lib=static=ntt");
    println!("cargo:rustc-link-lib=static=ntt_cpu");
    println!("cargo:rustc-link-lib=static=poly_mul");
    println!("cargo:rustc-link-lib=static=poly_mul_cpu");
    if cfg!(target_os = "macos") { println!("cargo:rustc-link-lib=c++"); } else { println!("cargo:rustc-link-lib=stdc++"); }
}
