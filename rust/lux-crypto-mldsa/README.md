# lux-crypto-mldsa

Canonical Rust binding for **ML-DSA** (FIPS 204), the NIST-standardized
post-quantum signature scheme (formerly Dilithium).

Wraps the C-ABI exposed by `luxcpp/crypto/mldsa`. Verified against the NIST
FIPS 204 reference vectors.

## Algorithm

- **ML-DSA** -- FIPS 204
- Modes: ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (NIST levels 2/3/5)
- Key generation, signing, verification

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libmldsa_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-mldsa
```

## Attribution

Underlying implementation derived from PQClean (CC0 / public domain).

## License

See `LICENSE` at the repository root.
