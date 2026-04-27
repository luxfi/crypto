# lux-crypto Rust workspace coverage

Workspace at `/Users/z/work/lux/crypto/rust/` containing the per-algorithm
canonical Rust bindings to `luxcpp/crypto`.

## Workspace summary (2026-04-27)

| Metric | Value |
|---|---|
| Workspace member crates | **3** (1 umbrella + 2 per-algorithm) |
| Workspace tests passing | **27 / 27** |
| Workspace tests failing | **0** |
| Tests asserting byte-equality vs published spec vectors | **15** |
| Build cmd | `CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-canonical cargo test --workspace --release` |

## Member crates

| Crate | Wraps | C-ABI archive | Tests | Spec source |
|---|---|---|---:|---|
| `lux-crypto` | umbrella (raw FFI surface, backward compat) | n/a | 9 | discriminator coverage |
| `lux-crypto-keccak` | `lux_keccak256` | `keccak/libkeccak_cpu.a` | 12 | keccak.team / Ethereum Yellow Paper App. F / `eth_hash` Python (cross-checked) |
| `lux-crypto-secp256k1` | `lux_secp256k1_ecrecover{,_batch}` | `secp256k1/libsecp256k1_cpu.a` | 6 | SEC1 v2 sec. 4.1.6 / EVM Yellow Paper App. E / `eth_keys` Python (cross-checked) |

Spec-vector tests assert byte-equality to independently-verified reference
values, not equality to a sibling Lux implementation. The Python `eth_hash`
and `eth_keys` libraries used for cross-check are the canonical Ethereum
reference implementations and call into the audited `coincurve`/libsecp256k1
backend.

## Per-algorithm spec vectors

### keccak (12 tests)

| Test | Input | Source |
|---|---|---|
| `empty_string` | `""` | keccak.team / Yellow Paper |
| `abc` | `"abc"` | keccak.team |
| `message_digest` | `"message digest"` | classical hash test corpus |
| `quick_brown_fox` | pangram | Trezor / Ethereum CI |
| `quick_brown_fox_period` | pangram + `.` | avalanche check |
| `single_zero_byte` | `0x00` | OpenZeppelin / Bouncy Castle |
| `thirty_one_zero_bytes` | 31 x `0x00` | padding-boundary edge case |
| `one_hundred_thirty_five_zero_bytes` | 135 x `0x00` | sponge-rate boundary (1088 bits = 136 bytes) |
| `two_thousand_forty_eight_byte_incrementing_input` | 2048 incrementing bytes | multi-block absorption |
| `one_million_a` | 1,000,000 x `'a'` | classic SHA-family stress vector |
| `hash_into_is_equivalent_to_hash` | API equivalence | n/a |
| `deterministic_across_calls` | repeated input | invariant |

### secp256k1 (6 tests = 2 unit + 4 integration)

| Test | Coverage |
|---|---|
| `status_from_int_round_trip` | enum mapping for status codes 0..=7 + invalid |
| `batch_input_stride_is_correct` | record width = 97 bytes (`hash || r || s || v`) |
| `ecrecover_known_vectors` | 3 distinct keypairs / messages, recovered pubkey == expected |
| `ecrecover_v_low_bit_selects_recid` | C-ABI takes `v & 1` for recid (matches libsecp256k1 convention) |
| `ecrecover_batch_round_trip` | 3 vectors via batch path produce same pubkeys |
| `ecrecover_batch_rejects_misaligned_input` | input length not multiple of 97 -> Err(BadInput) |

## Crates not yet in this workspace (deferred, not stubbed)

The following per-algorithm crates were **intentionally not shipped** in this
pass. The luxcpp/crypto C-ABI for each currently returns
`CRYPTO_ERR_NOTIMPL = -5` for the cryptographic operation, meaning the
underlying body is still a stub awaiting a sibling agent's implementation.
Per the workspace policy (no compatibility shims, no fake stubs), a Rust
crate is added only after its C-ABI returns real cryptographic output that
matches a published spec vector.

| Algorithm | C-ABI archive | Symbol presence | Body status |
|---|---|:-:|---|
| sha256 | `sha256/libsha256_cpu.a` | 0 lux_* symbols | not wired to C-ABI |
| ripemd160 | `ripemd160/libripemd160_cpu.a` | 0 lux_* symbols | not wired to C-ABI |
| blake2b | `blake2b/libblake2b_cpu.a` | 0 lux_* symbols | not wired to C-ABI |
| poly_mul | `poly_mul/libpoly_mul_cpu.a` | 0 lux_* symbols | not wired to C-ABI |
| evm256 | `evm256/libevm256_cpu.a` | 0 lux_* symbols (uses modexp archive instead) | not wired to C-ABI |
| blake3 | `blake3/libblake3_cpu.a` | 2 lux_* symbols | symbol aliased to keccak (returns wrong digest) |
| ed25519 | `ed25519/libed25519_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| sr25519 | `sr25519/libsr25519_cpu.a` | 2 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| secp256r1 | `secp256r1/libsecp256r1_cpu.a` | 1 lux_* symbol | returns `CRYPTO_ERR_NOTIMPL` |
| mldsa | `mldsa/libmldsa_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| mlkem | `mlkem/libmlkem_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| slhdsa | `slhdsa/libslhdsa_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| bls (BLS12-381) | `bls/libbls_cpu.a` | 8 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| bn254 | `bn254/libbn254_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| modexp | `modexp/libmodexp_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| aead | `aead/libaead_cpu.a` | 2 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| poseidon | `poseidon/libposeidon_cpu.a` | 2 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| pedersen | `pedersen/libpedersen_cpu.a` | 2 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| ipa | `ipa/libipa_cpu.a` | 2 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| verkle | `verkle/libverkle_cpu.a` | 2 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| kzg | `kzg/libkzg_cpu.a` | 4 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| lamport | `lamport/liblamport_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| ntt | `ntt/libntt_cpu.a` | 3 lux_* symbols | all return `CRYPTO_ERR_NOTIMPL` |
| frost | `frost/libfrost_cpu.a` | 5 lux_* symbols | likely `CRYPTO_ERR_NOTIMPL` |
| cggmp21 | `cggmp21/libcggmp21_cpu.a` | 5 lux_* symbols | likely `CRYPTO_ERR_NOTIMPL` |
| ringtail | `ringtail/libringtail_cpu.a` | 4 lux_* symbols | likely `CRYPTO_ERR_NOTIMPL` |

When a sibling agent lands a real body (e.g. issue #92 for blake3+poseidon,
#93 for ipa/poly_mul/pedersen/verkle, #94 for bn254/secp256r1/kzg/modexp/evm256),
admission to this workspace requires:

1. A non-trivial body in `luxcpp/crypto/<alg>/c-abi/c_<alg>.cpp` (not
   `return CRYPTO_ERR_NOTIMPL`).
2. A reproducible smoke test against a published spec vector before the Rust
   crate is added (see e.g. the ed25519 RFC 8032 §7 vectors, mldsa NIST FIPS
   204 KAT files, mlkem FIPS 203 KAT, slhdsa FIPS 205 KAT, BLS12-381 ETH2
   spec vectors, BN254 EVM precompile vectors, KZG `c-kzg-4844` test vectors).
3. A Rust integration test in `lux-crypto-<alg>/tests/spec_vectors.rs`
   asserting byte-equality against those vectors.

## Reproducing the test sweep

```sh
cd /Users/z/work/lux/crypto/rust
CRYPTO_BUILD_DIR=/Users/z/work/luxcpp/crypto/build-canonical \
    cargo test --workspace --release
```

Expected output: 27 tests pass, 0 fail, 0 ignored.

## Method

```
RUSTFLAGS="-C instrument-coverage" cargo test --workspace --no-run
# locate per-crate test binaries under target/release/deps and run with
# LLVM_PROFILE_FILE; merge profraws and emit a per-crate report.
```

The umbrella crate's coverage methodology described in this file's prior
revision still applies to its own line/function coverage. Each per-algorithm
crate's coverage is dominated by integration tests asserting against
published spec vectors; the unit-level discriminator tests cover the
remaining pure-Rust enum mapping.
