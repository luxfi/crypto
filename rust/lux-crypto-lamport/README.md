# lux-crypto-lamport

Canonical Rust binding for **Lamport one-time signatures** (Lamport 1979).

Wraps the C-ABI exposed by `luxcpp/crypto/lamport`. Hash-based, post-quantum,
single-use. Per-key state must be enforced by callers.

## Algorithm

- **Lamport OTS** -- Lamport 1979
- Hash-based, post-quantum
- One-time use; reusing a key reveals the secret

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `liblamport_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-lamport
```

## License

See `LICENSE` at the repository root.
