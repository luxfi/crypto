# lux-crypto-sha256

Canonical Rust binding for **SHA-256** (FIPS 180-4).

Wraps the C-ABI exposed by `luxcpp/crypto/sha256`. Verified against FIPS 180-4
reference vectors.

## Algorithm

- **SHA-256** -- 32-byte digest, FIPS 180-4 standard

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libsha256_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-sha256
```

## License

See `LICENSE` at the repository root.
