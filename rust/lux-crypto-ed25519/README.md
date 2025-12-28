# lux-crypto-ed25519

Canonical Rust binding for **Ed25519** (RFC 8032).

Wraps the C-ABI exposed by `luxcpp/crypto/ed25519` (vendored ed25519-donna,
public domain). Verified against the RFC 8032 reference vectors.

## Algorithm

- **Ed25519** -- EdDSA over edwards25519, RFC 8032
- Keygen / sign / verify

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libed25519_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-ed25519
```

## Attribution

Vendored `ed25519-donna` (Andrew Moon, public domain).

## License

See `LICENSE` at the repository root.
