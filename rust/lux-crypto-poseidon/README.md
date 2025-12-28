# lux-crypto-poseidon

Canonical Rust binding for **Poseidon2** hash with t=2 over BN254 scalar field.

Wraps the C-ABI exposed by `luxcpp/crypto/poseidon`. Round constants and
permutation match `gnark-crypto` v0.20.1 for byte-for-byte cross-stack
compatibility.

## Algorithm

- **Poseidon2** -- ZK-friendly hash, BN254 scalar field
- Width: t=2 (compression mode)
- gnark-crypto v0.20.1 compatible

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libposeidon_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-poseidon
```

## Attribution

Round constants and permutation derived from `gnark-crypto` v0.20.1
(Apache 2.0).

## License

See `LICENSE` at the repository root.
