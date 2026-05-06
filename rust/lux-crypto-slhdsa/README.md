# lux-crypto-slhdsa

Canonical Rust binding for Lux SLH-DSA (FIPS 205, the final standardized form
of SLH-DSA (FIPS 205, formerly SPHINCS+)).

**Status: stub — luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp returns
`CRYPTO_ERR_NOTIMPL`.** The Rust binding is shipped against the canonical
C-ABI surface; KAT-vector roundtrip tests are gated `#[ignore]` until the
C-ABI body lands. Tracked at `#slhdsa-c-abi-impl`.

## Use

```rust
use lux_crypto_slhdsa::{keygen, sign, verify, Mode};

let mode = Mode::Sha2_128f;
let mut pk = vec![0u8; mode.pk_len()];
let mut sk = vec![0u8; mode.sk_len()];
keygen(mode, &seed, &mut pk, &mut sk)?;
```

## Modes

| `Mode`       | NIST level | pk     | sk    | sig    |
|--------------|------------|--------|-------|--------|
| `Sha2_128f`  | L1         | 32     | 64    | 17088  |
| `Sha2_192f`  | L3         | 48     | 96    | 35664  |
| `Sha2_256f`  | L5         | 64     | 128   | 49856  |

## Source

C-ABI body: `luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp`.
