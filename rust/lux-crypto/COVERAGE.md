# lux-crypto Rust workspace coverage

Workspace at `/Users/z/work/lux/crypto/rust/` containing the per-algorithm
canonical Rust bindings to `luxcpp/crypto`.

## Workspace summary (2026-04-27)

| Metric | Value |
|---|---|
| Workspace member crates | **17** (1 umbrella + 16 per-algorithm) |
| Workspace tests passing | **182 / 182** |
| Workspace tests failing | **0** |
| Workspace tests ignored | **4** (SLH-DSA 192f/256f — slow, run with `--ignored`) |
| Build cmd | `CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-cto cargo test --workspace` |

## Member crates

| Crate | Wraps | C-ABI archive(s) | Tests | Spec source |
|---|---|---|---:|---|
| `lux-crypto` | umbrella raw FFI | n/a | 9 | discriminator coverage |
| `lux-crypto-keccak` | `keccak256` | `keccak/libkeccak_cpu.a` + `libkeccak.a` | 12 | keccak.team / Yellow Paper App. F |
| `lux-crypto-secp256k1` | `secp256k1_ecrecover{,_batch}` | `secp256k1/libsecp256k1_cpu.a` | 6 | SEC1 v2 §4.1.6 / Yellow Paper App. E |
| `lux-crypto-sha256` | `sha256` | `sha256/libsha256{,_cpu}.a` | 12 | FIPS 180-4 + RFC 6234 + python `hashlib` |
| `lux-crypto-ripemd160` | `ripemd160` | `ripemd160/libripemd160{,_cpu}.a` | 14 | Dobbertin et al. 1996 + python `hashlib` |
| `lux-crypto-blake2b` | `blake2b` | `blake2b/libblake2b{,_cpu}.a` | 13 | RFC 7693 App. A + python `hashlib` |
| `lux-crypto-aead` | `aead_chacha20poly1305_{seal,open}` | `aead/libaead{,_cpu}.a` | 11 | RFC 8439 §2.8.2 |
| `lux-crypto-lamport` | `lamport_{keygen,sign,verify}` | `lamport/liblamport{,_cpu}.a` + sha256 | 5 (10 KATs) | luxfi/crypto KAT corpus (10 NIST-style vectors) |
| `lux-crypto-mldsa` | `mldsa_{keygen,sign,verify}` | `mldsa/libmldsa{,_cpu}.a` (PQClean) | 13 | FIPS 204 §4 (modes 2/3/5) |
| `lux-crypto-mlkem` | `mlkem_{keygen,encap,decap}` | `mlkem/libmlkem{,_cpu}.a` (PQClean) | 12 | FIPS 203 §7 (modes 2/3/5) |
| `lux-crypto-slhdsa` | `slhdsa_{keygen,sign,verify}` | `slhdsa/libslhdsa{,_cpu}.a` (PQClean) | 9 (+4 ignored slow) | FIPS 205 §10 (sha2-128f, shake-128f) |
| `lux-crypto-banderwagon` | `banderwagon_*` | `banderwagon/libbanderwagon{,_cpu,_metal}.a` | 14 | crate-crypto/go-ipa + ethereum/banderwagon-py KATs |
| `lux-crypto-pedersen` | `pedersen_{commit,verify}` | `pedersen/libpedersen{,_cpu}.a` + ipa + banderwagon | 12 | banderwagon SRS w/ deterministic generators |
| `lux-crypto-ipa` | `ipa_{commit,multiproof_verify}` | `ipa/libipa{,_cpu}.a` + banderwagon | 12 | banderwagon SRS + 576-byte proof bundle |
| `lux-crypto-verkle` | `verkle_{commit,multiproof_verify}` | `verkle/libverkle{,_cpu}.a` + ipa + banderwagon | 12 | EIP-7805 verkle SRS |
| `lux-crypto-evm256` | `evm256_{addmod,mulmod}` | `evm256/libevm256{,_cpu}.a` | 4 (12 KATs) | EVM Yellow Paper §H.1 + intx/evmmax |
| `lux-crypto-kzg` | `kzg_verify_proof` (+ NOTIMPL surface) | `kzg/libkzg{,_cpu}.a` + sha256 + blst | 12 | EIP-4844 §3.4 / cevm precompiles_kzg_test.cpp |

Spec-vector tests assert byte-equality to independently-verified reference
values, not equality to a sibling Lux implementation. Cross-checks use
upstream tooling (Python `hashlib`, OpenSSL, eth_keys, c-kzg-4844, PQClean
KATs, gnark-crypto banderwagon vectors, RFC 8439 / RFC 7693 / FIPS PUB
appendix vectors).

## Crates not yet shipped (deferred — c-abi still NOTIMPL)

The following per-algorithm crates are **intentionally not shipped** in
this pass. The luxcpp/crypto C-ABI for each currently returns
`CRYPTO_ERR_NOTIMPL = -5` for the cryptographic operation, meaning the
underlying body is still a stub. Per workspace policy (no compatibility
shims, no fake stubs), a Rust crate is added only after its C-ABI returns
real cryptographic output that matches a published spec vector.

| Algorithm | C-ABI file | Status |
|---|---|---|
| blake3 | `blake3/c-abi/c_blake3.cpp` | All 2 entry points return `CRYPTO_ERR_NOTIMPL` |
| poseidon | `poseidon/c-abi/c_poseidon.cpp` | Both `_goldilocks` and `_bn254` return `CRYPTO_ERR_NOTIMPL` |
| ed25519 | `ed25519/c-abi/c_ed25519.cpp` | All 3 entry points return `CRYPTO_ERR_NOTIMPL` |
| bls (BLS12-381) | `bls/c-abi/c_bls.cpp` | All 8 entry points return `CRYPTO_ERR_NOTIMPL` (Phase 1 stub) |
| poly_mul | `poly_mul/c-abi/c_poly_mul.cpp` | File is empty — no `extern "C"` exports (NTT exposed via `ntt` crate when wired) |

## Partial wiring

| Algorithm | Notes |
|---|---|
| kzg | `kzg_verify_proof` is real (12 KATs incl. f(x)=0 and f(x)=1 vectors). The blob ops `kzg_blob_to_commit`, `kzg_commit_to_proof`, `kzg_verify_blob` live in a separate TU (`c_kzg_blob.cpp`) which is not in the current `libkzg.a` archive — they return NOTIMPL. The Rust crate exposes the API for forward compatibility and one test asserts the NOTIMPL surface. |
| banderwagon | `banderwagon_msm{,_compressed}` consult the Metal driver header at compile time, but the driver itself returns NOTIMPL and the body falls back to CPU — this is invisible to Rust callers. |

## Reproducing the test sweep

```sh
cd /Users/z/work/lux/crypto/rust
CRYPTO_BUILD_DIR=/Users/z/work/luxcpp/crypto/build-cto \
    cargo test --workspace
```

Expected output: 182 tests pass, 0 fail, 4 ignored.

To run the slow SLH-DSA 192f/256f variants:

```sh
CRYPTO_BUILD_DIR=/Users/z/work/luxcpp/crypto/build-cto \
    cargo test --workspace -- --ignored
```

## Spec-vector summary by crate

### sha256 (12 tests)
FIPS 180-4 / RFC 6234. Empty, "abc", FIPS Appendix B.2 56-byte alphabet,
1M "a" stress, single zero byte, 32 zeros, padding boundaries 55/56,
32-zero Ethereum slot, deterministic, hash_into, 2048-byte multi-block.

### ripemd160 (14 tests)
Dobbertin/Bosselaers/Preneel 1996 paper vectors: empty, "a", "abc",
"message digest", lowercase alphabet, alphanumeric, 1M "a", quick fox,
single zero, 32 zeros, padding boundaries 55/56, deterministic, hash_into.

### blake2b (13 tests)
RFC 7693 App. A: empty, "abc", "a", quick fox + period, single zero,
32 zeros, 127/128/129 zero-byte block-boundary, 1M "a" stress,
deterministic, hash_into.

### aead (11 tests)
RFC 8439 §2.8.2: canonical seal + open vectors, empty pt, empty AAD with
payload, tamper detection on ct/tag/AAD, 4096-byte payload round trip,
key isolation, deterministic seal, cross-nonce isolation.

### lamport (5 tests / 10 KAT vectors)
The single `kat_vectors_byte_equal_pk_and_signature_digests` test loops
over 10 vectors copied verbatim from `luxfi/crypto/lamport/kat_vectors_test.go`,
each pinning (seed, msg) -> (PK digest, signature digest). Plus tampered
signature, message-mismatch, keypair-mismatch, size-constant assertions.

### mldsa (13 tests, FIPS 204)
Round-trip + tamper detection across modes 2/3/5: keygen produces
(1312, 2560), (1952, 4032), (2592, 4896) byte buffers; signatures bounded
by 2420/3309/4627. Tamper detection on signature bit, message, public key.

### mlkem (12 tests, FIPS 203)
Round-trip across modes 512/768/1024: pk = 800/1184/1568, sk =
1632/2400/3168, ct = 768/1088/1568. Implicit-rejection invariant: a
tampered ct does not raise an error but produces a different shared
secret. Cross-keypair isolation.

### slhdsa (9 tests + 4 ignored slow, FIPS 205)
SHA2-128f and SHAKE-128f round-trips; 192f/256f gated `#[ignore]` due to
>5s/>30s keygen. Tamper detection on signature, message, keypair.
Empty-message and 4096-byte messages round-trip. Size constants per
Table 2 (32/64/17088, 48/96/35664, 64/128/49856).

### banderwagon (14 tests)
16 published `2^i * G` doublings (encode + decode round-trip) per
crate-crypto/go-ipa `element_test.go` corpus. G+G = 2G, G + (-G) =
identity, scalar_mul vs double, scalar_mul(0) = identity, MSM(G,1; G,1)
= 2G, MSM-compressed matches MSM-uncompressed, empty-MSM = identity.

### pedersen (12 tests)
Commit + verify round-trip with single, two, empty values; deterministic
output for fixed inputs; tamper detection on commit/values/blinding;
distinct blinding/values change commit; 256-element SRS cap enforced;
misaligned input rejected.

### ipa (12 tests)
Empty + zero coefficient = identity (32 zero bytes); deterministic
commit; distinct coefficients distinct commits; coefficient-0 alignment;
SRS cap (256) enforced; misaligned input rejected; full-SRS commit
succeeds; multiproof verifier rejects zero queries / mismatched lengths
/ invalid proof bundle.

### verkle (12 tests)
Empty + zero coefficient = identity; deterministic and distinct coeff
checks; alignment; SRS cap; full-SRS commit; multiproof verifier
negative tests.

### evm256 (4 tests / 12 KATs)
12 published vectors generated against Python big-int reference,
including: small primes, BLS12-381 Fr modulus, secp256k1 group order,
boundary cases at 2^256 - 1, and 2^256 - 2 squared. Zero-modulus is
explicitly tested and asserted to return `BadInput` (the body's
`m == 0` short-circuit). Deterministic-call invariant.

### kzg (12 tests)
Vectors mirrored from `luxcpp/crypto/kzg/test/kzg_test.cpp` which port
cevm's `precompiles_kzg_test.cpp`. Includes: f(x)=0 polynomial accepts,
f(x)=1 polynomial accepts (with the BLS12-381 G1 generator commitment),
reject z >= BLS_MODULUS, reject y >= BLS_MODULUS, reject off-curve
commitment, reject wrong proof for f(x)=1, reject y mismatch for
f(x)=0 / f(x)=1, deterministic-call invariant. Plus an explicit assertion
that the unwired blob ops surface `Internal(-5)` so callers see the
NOTIMPL error type at compile time rather than a panic.

## Architecture

Each per-algorithm crate is a thin Rust wrapper over the `extern "C"`
surface declared in `luxcpp/crypto/c-abi/lux_crypto.h`. Builds resolve
in this order:

1. `CRYPTO_DIR` env var (install prefix; expects `lib/<alg>/lib<alg>_cpu.a`).
2. `CRYPTO_BUILD_DIR` env var (cmake build dir; expects `<alg>/lib<alg>{,_cpu}.a`).
3. Default fallback to `../../../../luxcpp/crypto/build-cto`.

The umbrella archive `lib<alg>.a` typically contains only the c-abi shim
TU; the implementation body lives in `lib<alg>_cpu.a`. Crates that depend
on shared primitives (e.g. pedersen+ipa+verkle on banderwagon, kzg on
sha256+blst, lamport on sha256) explicitly link the additional archives.

On macOS arm64, the banderwagon shim was compiled with
`LUX_CRYPTO_HAS_METAL` so the c-abi references symbols in
`libbanderwagon_metal.a`. The driver returns NOTIMPL and the CPU
fallback path is taken transparently.
