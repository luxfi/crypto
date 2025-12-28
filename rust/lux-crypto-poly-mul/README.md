# lux-crypto-poly-mul

Canonical Rust binding for Lux negacyclic polynomial multiplication over
`Z_Q[X] / (X^n + 1)` for the Cyclone-FFT prime (Q = 998244353). Multiplies
via Schoolbook (n < 64) or NTT (n a power of two).

**Status: C++ body exists in `luxcpp/crypto/poly_mul/c-abi/c_poly_mul.cpp`,
but the symbol is exported from `libntt.a` and that lib's `c_ntt.cpp.o`
returns `CRYPTO_ERR_NOTIMPL`.** Tests are gated `#[ignore]` until the NTT
C-ABI body lands. Tracked at `#poly_mul-c-abi-impl`.

## Source

C-ABI body: `luxcpp/crypto/poly_mul/c-abi/c_poly_mul.cpp`.
