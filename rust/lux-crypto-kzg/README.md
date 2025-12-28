# lux-crypto-kzg

Canonical Rust binding for the **KZG point-evaluation precompile** (EIP-4844).

Wraps the C-ABI exposed by `luxcpp/crypto/kzg`.

## Algorithm

- **KZG polynomial commitment** -- as standardized in EIP-4844
- Uses the Ethereum trusted setup (KZG ceremony)

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libkzg_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-kzg
```

## Attribution

Underlying implementation derived from `c-kzg-4844` (Apache 2.0). Trusted
setup from the Ethereum KZG ceremony.

## License

See `LICENSE` at the repository root.
