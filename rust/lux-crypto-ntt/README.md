# lux-crypto-ntt

Canonical Rust binding for the Lux **Number-Theoretic Transform** over the
Cyclone-FFT prime `Q = 998244353`.

Wraps the C-ABI exposed by `luxcpp/crypto/ntt`.

## Algorithm

- **NTT over Q = 998244353** (a 23-bit Solinas prime, primitive 2^23-th root of unity)
- Forward / inverse transform
- Used as a primitive for lattice-based schemes and polynomial multiplication

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libntt_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-ntt
```

## License

See `LICENSE` at the repository root.
