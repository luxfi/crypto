# lux-crypto-slhdsa

Canonical Rust binding for **SLH-DSA** (FIPS 205), the NIST-standardized
hash-based stateless post-quantum signature scheme (formerly SPHINCS+).

Wraps the C-ABI exposed by `luxcpp/crypto/slhdsa`. Verified against the NIST
FIPS 205 reference vectors.

## Algorithm

- **SLH-DSA** -- FIPS 205, hash-based, stateless
- Multiple parameter sets (SHA2-128f / SHA2-192f / SHA2-256f and SHAKE variants)

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libslhdsa_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-slhdsa
```

## Attribution

Underlying implementation derived from PQClean (CC0 / public domain).

## License

See `LICENSE` at the repository root.
