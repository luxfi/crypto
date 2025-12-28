# lux-crypto-sha256

Canonical Rust binding for Lux SHA-256 (FIPS 180-4).

Wraps `sha256` from `luxcpp/crypto/sha256`. The C-ABI header is
`luxcpp/crypto/c-abi/lux_crypto.h`.

## Use

```rust
use lux_crypto_sha256::hash;

let digest = hash(b"abc");
```

## Test vectors

`tests/spec_vectors.rs` covers the FIPS 180-4 §A reference vectors:
- `abc` (§A.1)
- `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` (§A.2)
- one million 'a' bytes (§A.3)

## Source

C-ABI body: `luxcpp/crypto/sha256/c-abi/c_sha256.cpp`.
