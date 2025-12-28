# lux-crypto-bls

Canonical Rust binding for Lux BLS12-381 signatures and aggregation.

Conforms to draft-irtf-cfrg-bls-signature-05 ("min_pk" variant: 48-byte public
key, 96-byte signature).

**Status: stub — `c_bls.cpp` returns `CRYPTO_ERR_NOTIMPL`.** Tests gated
`#[ignore]`. Tracked at `#bls-c-abi-impl`.

## Use

```rust
use lux_crypto_bls::{keygen, sign, sk_to_pk, verify, aggregate_sigs};
```

## Source

C-ABI body: `luxcpp/crypto/bls/c-abi/c_bls.cpp`.
