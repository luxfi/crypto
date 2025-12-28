# lux-crypto-verkle

Canonical Rust binding for **Verkle** commit and multiproof verification using
the Banderwagon SRS.

Wraps the C-ABI exposed by `luxcpp/crypto/verkle`.

## Algorithm

- **Verkle tree** -- commit, multiproof, verify
- IPA over Banderwagon (see `lux-crypto-ipa`, `lux-crypto-banderwagon`)

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libverkle_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-verkle
```

## Attribution

Banderwagon SRS from the public Verkle ceremony.

## License

See `LICENSE` at the repository root.
