# lux-crypto-keccak

Canonical Rust binding for Lux keccak256.

Wraps the `keccak256` symbol exported by `luxcpp/crypto/keccak`. The C-ABI
header is `luxcpp/crypto/include/lux/crypto/keccak.h`. The body is a
first-party Keccak Reference v3.0 implementation with the Ethereum padding
byte `0x01` (NOT FIPS 202 SHA3-256, which uses `0x06`).

## Use

```rust
use lux_crypto_keccak::hash;

let digest = hash(b"abc");
```

## Build

The build script discovers `libkeccak.a` and `libkeccak_cpu.a` in the order:

1. `CRYPTO_DIR` environment variable (install prefix; archive at `$CRYPTO_DIR/lib/keccak/`).
2. `CRYPTO_BUILD_DIR` environment variable (cmake build dir; archive at `$CRYPTO_BUILD_DIR/keccak/`).
3. Default fallback to `../../../../luxcpp/crypto/build-cto/keccak/`.

```bash
CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-cto cargo build --release
```

## Test vectors

`tests/spec_vectors.rs` covers the standard reference vectors (empty input,
"abc", "The quick brown fox jumps over the lazy dog", a million 'a' bytes,
sponge-rate boundary cases). All vectors are independently verified against
`eth_hash` (PyPA) and the keccak.team reference.

## License

`Apache-2.0 OR MIT` (workspace default is `BSD-3-Clause`; this crate inherits).

## Source

C-ABI body: `luxcpp/crypto/keccak/c-abi/c_keccak.cpp`.
