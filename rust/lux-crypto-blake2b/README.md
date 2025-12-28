# lux-crypto-blake2b

Canonical Rust binding for Lux BLAKE2b-512 (RFC 7693).

Wraps `blake2b` from `luxcpp/crypto/blake2b`.

## Use

```rust
use lux_crypto_blake2b::hash;

let digest = hash(b"abc");
```

## Test vectors

`tests/spec_vectors.rs` covers RFC 7693 §F.4 reference vectors.

## Source

C-ABI body: `luxcpp/crypto/blake2b/c-abi/c_blake2b.cpp`.
