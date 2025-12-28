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
            .join("luxcpp").join("crypto").join("build-cto")
    };
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_DIR");
    println!("cargo:rerun-if-env-changed=CRYPTO_BUILD_DIR");
    // The evm256 functions (evm256_mulmod, evm256_addmod) are exported from
    // libmodexp.a alongside modexp itself. The empty libevm256.a is a
    // placeholder for future kernel-side dispatch.
    let modexp_path = base.join("modexp");
    println!("cargo:rustc-link-search=native={}", modexp_path.display());
    println!("cargo:rustc-link-lib=static=modexp");
    println!("cargo:rustc-link-lib=static=modexp_cpu");
    if cfg!(target_os = "macos") { println!("cargo:rustc-link-lib=c++"); } else { println!("cargo:rustc-link-lib=stdc++"); }
}
