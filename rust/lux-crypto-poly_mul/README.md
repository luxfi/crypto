# lux-crypto-poly_mul

Canonical Rust binding for Lux **polynomial multiplication** over
`Z_Q[X] / (X^n + 1)` with `Q = 998244353` (negacyclic convolution).

Wraps the C-ABI exposed by `luxcpp/crypto/poly_mul`.

## Algorithm

- **Polynomial multiplication** in `Z_Q[X] / (X^n + 1)` (negacyclic ring)
- Built on top of `lux-crypto-ntt`
- Used as a primitive for lattice-based schemes (ML-DSA, ML-KEM, Pulsar)

## Build

Set `CRYPTO_DIR` (install prefix) or `CRYPTO_BUILD_DIR` (cmake build dir) so
the build script can find `libpoly_mul_cpu.a`.

```bash
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto-poly_mul
```

## License

See `LICENSE` at the repository root.
