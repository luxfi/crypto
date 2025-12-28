# lux-crypto-ipa

Canonical Rust binding for the **Inner Product Argument (IPA)** over
Banderwagon, as specified for Verkle trees (EIP-7805).

Wraps the C-ABI exposed by `luxcpp/crypto/ipa`.

## Algorithm

- **IPA** -- inner product argument, Banderwagon group
- Used to prove Verkle multiproofs

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libipa_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-ipa
```

## License

See `LICENSE` at the repository root.
