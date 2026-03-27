use std::env;
use std::path::PathBuf;

fn main() {
    // Search order for libluxcrypto:
    // 1. LUX_CRYPTO_LIB_DIR env var
    // 2. ~/work/lux/crypto/dist/
    // 3. System library path

    if let Ok(lib_dir) = env::var("LUX_CRYPTO_LIB_DIR") {
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
