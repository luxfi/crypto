# lux-crypto

Umbrella Rust binding to the Lux cryptography library (`luxcpp/crypto`). This
crate re-exports the per-algorithm member crates and retains the original raw
FFI surface for historical callers.

For new code, prefer the per-algorithm crates:

| Crate | Algorithm | Spec |
|-------|-----------|------|
| `lux-crypto-secp256k1` | secp256k1 ECDSA public-key recovery | SEC1, EIP-2 |
| `lux-crypto-keccak` | Keccak-256 | Ethereum Yellow Paper |
| `lux-crypto-sha256` | SHA-256 | FIPS 180-4 |
| `lux-crypto-ripemd160` | RIPEMD-160 | ISO/IEC 10118-3 |
| `lux-crypto-blake2b` | BLAKE2b | RFC 7693 |
| `lux-crypto-blake3` | BLAKE3 | BLAKE3 reference v1.5.0 |
| `lux-crypto-ed25519` | Ed25519 | RFC 8032 |
| `lux-crypto-aead` | ChaCha20-Poly1305 | RFC 8439 |
| `lux-crypto-bls` | BLS12-381 IRTF signatures | draft-irtf-cfrg-bls-signature-05 |
| `lux-crypto-mldsa` | ML-DSA | FIPS 204 |
| `lux-crypto-mlkem` | ML-KEM | FIPS 203 |
| `lux-crypto-slhdsa` | SLH-DSA | FIPS 205 |
| `lux-crypto-lamport` | Lamport OTS | Lamport 1979 |
| `lux-crypto-banderwagon` | Banderwagon group | EIP-7805 |
| `lux-crypto-pedersen` | Pedersen commitments | Verkle |
| `lux-crypto-ipa` | Inner Product Argument | Verkle |
| `lux-crypto-verkle` | Verkle commit + multiproof | Verkle |
| `lux-crypto-evm256` | EVM 256-bit modular arithmetic | EIP-7212 helpers |
| `lux-crypto-kzg` | KZG point-evaluation precompile | EIP-4844 |
| `lux-crypto-poseidon` | Poseidon2 t=2 BN254 | gnark-crypto v0.20.1 |
| `lux-crypto-ntt` | Number-Theoretic Transform | Q = 998244353 |
| `lux-crypto-poly_mul` | Polynomial multiplication in `Z_Q[X]/(X^n+1)` | Q = 998244353 |

## Build

The crate links static archives produced by `luxcpp/crypto`. Set one of:

- `CRYPTO_DIR` -- install prefix; archives at `$CRYPTO_DIR/lib/<alg>/lib<alg>_cpu.a`
- `CRYPTO_BUILD_DIR` -- cmake build directory; archives at `$CRYPTO_BUILD_DIR/<alg>/lib<alg>_cpu.a`

If neither is set the build script falls back to a sibling checkout of
`luxcpp/crypto` at `../../../../luxcpp/crypto/build-cto`.

```bash
# Build the C archives once
git clone https://github.com/luxfi/crypto
cd crypto && cmake -S . -B build-cto && cmake --build build-cto

# Build this crate against them
export CRYPTO_BUILD_DIR=$(pwd)/build-cto
cargo build -p lux-crypto
```

## License

See `LICENSE` at the repository root. Source files declare `SPDX-License-Identifier`
per file; the umbrella project license is the Lux Ecosystem License.
