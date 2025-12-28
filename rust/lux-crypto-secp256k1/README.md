# lux-crypto-secp256k1

Canonical Rust binding for **secp256k1 ECDSA public-key recovery** (Ethereum-style
`ecrecover`).

Wraps the C-ABI exposed by `luxcpp/crypto/secp256k1`. Single and batch recovery
APIs. Verified against SEC1 and EIP-2 reference vectors in `tests/`.

## Algorithm

- **secp256k1** -- Bitcoin/Ethereum curve (SEC1)
- **ECDSA recovery** -- recover the signer public key from `(msg, r, s, v)`
- Strict `s` low-S enforcement (EIP-2)

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so the
build script can find `libsecp256k1_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-secp256k1
```

## License

See `LICENSE` at the repository root.
