# lux-crypto-evm256

Canonical Rust binding for EVM **256-bit modular arithmetic primitives**
(`addmod`, `mulmod`, `expmod` helpers).

Wraps the C-ABI exposed by `luxcpp/crypto/evm256`.

## Algorithm

- **EVM 256-bit big integer arithmetic** -- modular add, mul, exp
- Constant-time where required by the EVM spec

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libevm256_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-evm256
```

## Attribution

Underlying big-integer routines derived from `intx` and `evmmax` (Apache 2.0).

## License

See `LICENSE` at the repository root.
