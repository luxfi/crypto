# lux-crypto-blake2b

Canonical Rust binding for **BLAKE2b** (RFC 7693).

Wraps the C-ABI exposed by `luxcpp/crypto/blake2b`. Verified against the
RFC 7693 reference vectors.

## Algorithm

- **BLAKE2b** -- variable digest length up to 64 bytes, RFC 7693

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libblake2b_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-blake2b
```

## License

See `LICENSE` at the repository root.
