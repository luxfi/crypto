# lux-crypto-pedersen

Canonical Rust binding for **Pedersen vector commitments** over Banderwagon.

Wraps the C-ABI exposed by `luxcpp/crypto/pedersen`. Used as the commitment
primitive for Verkle trees.

## Algorithm

- **Pedersen vector commitment** -- linear, hiding, binding
- Group: Banderwagon (`lux-crypto-banderwagon`)

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libpedersen_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-pedersen
```

## License

See `LICENSE` at the repository root.
