# lux-crypto-blake3

Canonical Rust binding for **BLAKE3** (vendored BLAKE3 reference v1.5.0).

Wraps the C-ABI exposed by `luxcpp/crypto/blake3`. Verified against the
official BLAKE3 KAT vector set (140 vectors) in `tests/`.

## Algorithm

- **BLAKE3** -- extendable-output hash (XOF) and 32-byte digest mode
- Vendored reference implementation v1.5.0

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libblake3_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-blake3
```

## Attribution

BLAKE3 reference code is licensed under CC0 1.0 / Apache 2.0 (dual-licensed).

## License

See `LICENSE` at the repository root.
