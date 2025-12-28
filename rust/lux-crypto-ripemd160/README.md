# lux-crypto-ripemd160

Canonical Rust binding for Lux RIPEMD-160 (Dobbertin/Bosselaers/Preneel 1996).

Wraps `ripemd160` from `luxcpp/crypto/ripemd160`. Used by Bitcoin/Ethereum
addresses (`RIPEMD160(SHA256(pk))`) and the EVM `RIPEMD160` precompile at
address 0x03.

## Use

```rust
use lux_crypto_ripemd160::hash;

let digest = hash(b"abc");
```

## Source

C-ABI body: `luxcpp/crypto/ripemd160/c-abi/c_ripemd160.cpp`.
