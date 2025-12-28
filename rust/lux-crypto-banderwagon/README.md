# lux-crypto-banderwagon

Canonical Rust binding for **Banderwagon**, the prime-order subgroup of the
Bandersnatch curve used in Verkle commitments.

Wraps the C-ABI exposed by `luxcpp/crypto/banderwagon`.

## Algorithm

- **Banderwagon** -- prime-order subgroup of Bandersnatch (twisted Edwards over BLS12-381 scalar)
- Used as the base group for Pedersen / IPA / Verkle

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libbanderwagon_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-banderwagon
```

## Attribution

Curve constants derived from the public Banderwagon SRS.

## License

See `LICENSE` at the repository root.
