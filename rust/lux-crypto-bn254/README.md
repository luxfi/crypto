# lux-crypto-bn254

Canonical Rust binding for Lux BN254 (alt_bn128) pairing-based EVM precompiles
at addresses 0x06 (add), 0x07 (mul), 0x08 (pairing).

**Status: stub — `c_bn254.cpp` returns `CRYPTO_ERR_NOTIMPL`.** Tests gated
`#[ignore]`. Tracked at `#bn254-c-abi-impl`.

## Source

C-ABI body: `luxcpp/crypto/bn254/c-abi/c_bn254.cpp`.
