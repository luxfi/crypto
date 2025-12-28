# lux-crypto-ripemd160

Canonical Rust binding for **RIPEMD-160** (ISO/IEC 10118-3, used in Bitcoin
P2PKH addresses).

Wraps the C-ABI exposed by `luxcpp/crypto/ripemd160`. Verified against the
RIPEMD-160 reference vectors.

## Algorithm

- **RIPEMD-160** -- 20-byte digest, ISO/IEC 10118-3

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libripemd160_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-ripemd160
```

## License

See `LICENSE` at the repository root.
