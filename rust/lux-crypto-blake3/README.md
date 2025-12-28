# lux-crypto-blake3

Canonical Rust binding for Lux BLAKE3.

**Status: stub — luxcpp/crypto/blake3/c-abi/c_blake3.cpp returns
`CRYPTO_ERR_NOTIMPL`.** The Rust binding is shipped against the canonical
C-ABI surface so downstream consumers can wire against a stable signature.
Spec-vector tests are gated `#[ignore]` until the C-ABI body lands; they are
tracked at `#blake3-c-abi-impl`.

## Use

```rust
use lux_crypto_blake3::hash;

let digest = hash(b"abc")?;
```

## Source

C-ABI body: `luxcpp/crypto/blake3/c-abi/c_blake3.cpp`.
