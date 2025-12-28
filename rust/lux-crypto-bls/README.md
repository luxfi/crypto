# lux-crypto-bls

Canonical Rust binding for **BLS12-381 IRTF signatures**
(`draft-irtf-cfrg-bls-signature-05`).

Wraps the C-ABI exposed by `luxcpp/crypto/bls`. Verified against the IRTF
reference vectors.

## Algorithm

- **BLS** -- BLS12-381 pairing-based signatures
- IETF draft `draft-irtf-cfrg-bls-signature-05`
- Used by Ethereum 2.0 / consensus and as the classical layer of Quasar

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libbls_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-bls
```

## License

See `LICENSE` at the repository root.
