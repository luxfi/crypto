# lux-crypto-ntt

Canonical Rust binding for Lux NTT (Number Theoretic Transform). Used by FHE
primitives.

**Status: stub — `c_ntt.cpp` returns `CRYPTO_ERR_NOTIMPL` for forward, inverse,
poly_mul.** Tests gated `#[ignore]`. Tracked at `#ntt-c-abi-impl`.

## Source

C-ABI body: `luxcpp/crypto/ntt/c-abi/c_ntt.cpp`.
