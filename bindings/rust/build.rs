use std::env;
use std::path::PathBuf;

fn read_lib_dir() -> Option<String> {
    if let Ok(v) = env::var("CRYPTO_LIB_DIR") {
        return Some(v);
    }
    if let Ok(v) = env::var("LUX_CRYPTO_LIB_DIR") {
        println!("cargo:warning=LUX_CRYPTO_LIB_DIR is deprecated; use CRYPTO_LIB_DIR");
        return Some(v);
    }
    None
}

fn main() {
    // Search order for libluxcrypto:
    // 1. CRYPTO_LIB_DIR env var (deprecated alias: LUX_CRYPTO_LIB_DIR)
    // 2. ~/work/lux/crypto/dist/
    // 3. System library path

    if let Some(lib_dir) = read_lib_dir() {
        println!("cargo:rustc-link-search=native={lib_dir}");
    } else {
        // Dev default: ~/work/lux/crypto/dist/
        if let Some(home) = env::var_os("HOME") {
            let dist = PathBuf::from(home).join("work/lux/crypto/dist");
            if dist.exists() {
                println!("cargo:rustc-link-search=native={}", dist.display());
            }
        }
    }

    println!("cargo:rerun-if-env-changed=CRYPTO_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LUX_CRYPTO_LIB_DIR");
    println!("cargo:rustc-link-lib=dylib=luxcrypto");

    // macOS: set rpath for all link targets (binaries, tests, examples)
    if cfg!(target_os = "macos") {
        // Always include /usr/local/lib as rpath fallback
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");

        if let Some(home) = env::var_os("HOME") {
            let dist = PathBuf::from(home).join("work/lux/crypto/dist");
            if dist.exists() {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dist.display());
            }
        }
    }
}
