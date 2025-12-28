# lux-crypto-ed25519

Canonical Rust binding for Lux Ed25519 (RFC 8032 §5.1, PureEdDSA over
Curve25519).

**Status: stub — luxcpp/crypto/ed25519/c-abi/c_ed25519.cpp returns
`CRYPTO_ERR_NOTIMPL`.** The Rust binding is shipped against the canonical
C-ABI surface; RFC 8032 §7.1 spec-vector tests are gated `#[ignore]` and
will be re-enabled when the C-ABI body lands. Tracked at `#ed25519-c-abi-impl`.

## Use

```rust
use lux_crypto_ed25519::{keygen, sign, verify};

let (sk, pk) = keygen(&seed)?;
let sig = sign(&sk, msg)?;
verify(&pk, msg, &sig)?;
```

## Source

C-ABI body: `luxcpp/crypto/ed25519/c-abi/c_ed25519.cpp`.
