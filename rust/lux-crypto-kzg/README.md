# lux-crypto-kzg

Canonical Rust binding for Lux KZG polynomial commitments (EIP-4844).

128 KiB blob shape (4096 × 32 bytes), 48-byte BLS12-381 G1 commitments and
proofs.

**Status: stub — `c_kzg.cpp` returns `CRYPTO_ERR_NOTIMPL`.** Tests gated
`#[ignore]`. Tracked at `#kzg-c-abi-impl`.

## Source

C-ABI body: `luxcpp/crypto/kzg/c-abi/c_kzg.cpp`.
