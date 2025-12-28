# lux-crypto-mldsa

Canonical Rust binding for Lux ML-DSA (FIPS 204, final standardized form of
CRYSTALS-Dilithium).

| Mode        | NIST level | pk     | sk    | sig    |
|-------------|------------|--------|-------|--------|
| `Mode2`     | L2         | 1312   | 2560  | 2420   |
| `Mode3`     | L3         | 1952   | 4032  | 3309   |
| `Mode5`     | L5         | 2592   | 4896  | 4627   |

**Status: stub — `c_mldsa.cpp` returns `CRYPTO_ERR_NOTIMPL`.** Tests gated
`#[ignore]`. Tracked at `#mldsa-c-abi-impl`.

## Source

C-ABI body: `luxcpp/crypto/mldsa/c-abi/c_mldsa.cpp`.
