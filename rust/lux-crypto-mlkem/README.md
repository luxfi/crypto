# lux-crypto-mlkem

Canonical Rust binding for Lux ML-KEM (FIPS 203, final standardized form of
CRYSTALS-Kyber).

| Mode        | NIST level | pk     | sk    | ct    | ss |
|-------------|------------|--------|-------|-------|----|
| `Mode2`     | L1         | 800    | 1632  | 768   | 32 |
| `Mode3`     | L3         | 1184   | 2400  | 1088  | 32 |
| `Mode5`     | L5         | 1568   | 3168  | 1568  | 32 |

**Status: stub — `c_mlkem.cpp` returns `CRYPTO_ERR_NOTIMPL`.** Tests gated
`#[ignore]`. Tracked at `#mlkem-c-abi-impl`.

## Source

C-ABI body: `luxcpp/crypto/mlkem/c-abi/c_mlkem.cpp`.
