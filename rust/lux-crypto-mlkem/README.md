# lux-crypto-mlkem

Canonical Rust binding for **ML-KEM** (FIPS 203), the NIST-standardized
post-quantum key-encapsulation mechanism (formerly Kyber).

Wraps the C-ABI exposed by `luxcpp/crypto/mlkem`. Verified against the NIST
FIPS 203 reference vectors.

## Algorithm

- **ML-KEM** -- FIPS 203
- Modes: ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 (NIST levels 1/3/5)
- Key generation, encapsulation, decapsulation

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libmlkem_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-mlkem
```

## Attribution

Underlying implementation derived from PQClean (CC0 / public domain).

## License

See `LICENSE` at the repository root.
