# lux-crypto-keccak

Canonical Rust binding for **Keccak-256** as used in Ethereum (pre-NIST padding).

Wraps the C-ABI exposed by `luxcpp/crypto/keccak`. Verified against published
reference vectors in `tests/spec_vectors.rs`.

## Algorithm

- **Keccak-256** -- 32-byte digest, Ethereum padding rule (0x01 ... 0x80)
- Distinct from FIPS-202 SHA3-256 (different padding)

## Build

This crate links a static archive (`libkeccak_cpu.a`) produced by
`luxcpp/crypto`. Set one of:

- `CRYPTO_DIR` -- install prefix (archive at `$CRYPTO_DIR/lib/keccak/libkeccak_cpu.a`)
- `CRYPTO_BUILD_DIR` -- cmake build dir (archive at `$CRYPTO_BUILD_DIR/keccak/libkeccak_cpu.a`)

If neither is set the build script falls back to `../../../../luxcpp/crypto/build-cto`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-keccak
```

## License

See `LICENSE` at the repository root.
