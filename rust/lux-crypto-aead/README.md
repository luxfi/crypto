# lux-crypto-aead

Canonical Rust binding for **ChaCha20-Poly1305 AEAD** (RFC 8439).

Wraps the C-ABI exposed by `luxcpp/crypto/aead`. Verified against the RFC 8439
reference vectors.

## Algorithm

- **ChaCha20-Poly1305** -- AEAD, RFC 8439
- 256-bit key, 96-bit nonce, 16-byte tag

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libaead_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-aead
```

## License

See `LICENSE` at the repository root.
