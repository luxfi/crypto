# Lux Crypto — Rust Workspace

Cargo workspace containing one crate per cryptographic algorithm in
`luxcpp/crypto`, plus an `lux-crypto` umbrella crate that re-exports each
algorithm crate behind a Cargo feature.

Every per-algorithm crate is a thin Rust binding over the canonical C-ABI
in `luxcpp/crypto/c-abi/lux_crypto.h`. CPU bodies live in
`luxcpp/crypto/<alg>/c-abi/c_<alg>.cpp`. We do not ship third-party FFI
wrappers; the C/C++ is first-party at `luxcpp/crypto`.

## Crates

| Crate                  | C-ABI status      | Spec vectors          |
|------------------------|-------------------|-----------------------|
| `lux-crypto-keccak`    | wired             | keccak.team, eth-hash |
| `lux-crypto-secp256k1` | wired             | SEC1, eth-keys        |
| `lux-crypto-sha256`    | wired             | FIPS 180-4 §A         |
| `lux-crypto-ripemd160` | wired             | Dobbertin 1996        |
| `lux-crypto-blake2b`   | wired             | RFC 7693 §F.4         |
| `lux-crypto-blake3`    | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-ed25519`   | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-slhdsa`    | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-mldsa`     | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-mlkem`     | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-bls`       | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-kzg`       | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-bn254`     | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-aead`      | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-ipa`       | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-pedersen`  | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-lamport`   | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-ntt`       | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-poly-mul`  | NOTIMPL stub      | (gated `#[ignore]`)   |
| `lux-crypto-evm256`    | NOTIMPL stub      | (gated `#[ignore]`)   |

A NOTIMPL crate ships the canonical Rust binding but its underlying C-ABI
returns `CRYPTO_ERR_NOTIMPL` (-5). Roundtrip tests are gated `#[ignore]`
with a FIXME pointing at the tracking issue. A "binding returns NOTIMPL"
guard test runs by default to ensure the binding does not silently pass.

## Use one crate

```toml
[dependencies]
lux-crypto-keccak = "0.1"
```

```rust
let digest = lux_crypto_keccak::hash(b"abc");
```

## Use the umbrella

```toml
[dependencies]
# Default features: keccak, secp256k1, sha256, ripemd160
lux-crypto = "0.1"

# Pick a smaller subset:
lux-crypto = { version = "0.1", default-features = false, features = ["keccak"] }

# All working algorithms:
lux-crypto = { version = "0.1", default-features = false, features = ["working"] }

# Every per-algo crate including NOTIMPL stubs:
lux-crypto = { version = "0.1", default-features = false, features = ["all"] }
```

```rust
use lux_crypto::keccak;
let d = keccak::hash(b"abc");
```

## Build environment

Each crate's `build.rs` discovers static archives in this order:

1. `CRYPTO_DIR` — install prefix, archives at `$CRYPTO_DIR/lib/<alg>/lib<alg>.a`.
2. `CRYPTO_BUILD_DIR` — cmake build dir, archives at `$CRYPTO_BUILD_DIR/<alg>/lib<alg>.a`.
3. Default fallback to `../../../../luxcpp/crypto/build-cto/`.

```bash
# Build whole workspace
CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-cto cargo build --release --workspace

# Test whole workspace (run NOTIMPL guards too)
CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-cto cargo test --release --workspace

# Generate rustdoc
CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-cto cargo doc --no-deps --workspace
```

The build directory is configured by running `cmake` against `luxcpp/crypto/`
with the layout that produces one subdirectory per algorithm. The
`build-cto` directory used in CI contains both `lib<alg>.a` (C-ABI shim) and
`lib<alg>_cpu.a` (CPU body) per algorithm.

## GPU dispatch

The Rust crates only bind the **CPU** C-ABI surface. GPU-accelerated paths
(Metal, CUDA, WGSL) live in `luxcpp/accel` and are not exposed through
these crates. Consumers needing GPU dispatch should call
`github.com/luxfi/gpu` (Go) or `luxfi/accel` directly.

## Licensing

Workspace defaults to `BSD-3-Clause`. Individual crates are
`Apache-2.0 OR MIT` for permissive consumers. See each `Cargo.toml`.
