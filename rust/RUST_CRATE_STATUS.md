# Lux Crypto — Rust Crate Status

Per-crate state of the Rust workspace at `~/work/lux/crypto/rust/`.

`CRYPTO_BUILD_DIR=/Users/z/work/luxcpp/crypto/build-cto` for every check.

## Status table

| Crate                  | cargo check | cargo test (pass/ignored) | rustdoc | dry-run publish | metadata | README |
|------------------------|:-----------:|:-------------------------:|:-------:|:---------------:|:--------:|:------:|
| `lux-crypto`           | OK          | 9 / 0                     | OK      | OK              | OK       | OK     |
| `lux-crypto-aead`      | OK          | 1 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-blake2b`   | OK          | 3 / 0                     | OK      | OK              | OK       | OK     |
| `lux-crypto-blake3`    | OK          | 1 / 2                     | OK      | OK              | OK       | OK     |
| `lux-crypto-bls`       | OK          | 1 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-bn254`     | OK          | 3 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-ed25519`   | OK          | 1 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-evm256`    | OK          | 1 / 2                     | OK      | OK              | OK       | OK     |
| `lux-crypto-ipa`       | OK          | 2 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-keccak`    | OK          | 12 / 0                    | OK      | OK              | OK       | OK     |
| `lux-crypto-kzg`       | OK          | 2 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-lamport`   | OK          | 1 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-mldsa`     | OK          | 2 / 3                     | OK      | OK              | OK       | OK     |
| `lux-crypto-mlkem`     | OK          | 2 / 3                     | OK      | OK              | OK       | OK     |
| `lux-crypto-ntt`       | OK          | 2 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-pedersen`  | OK          | 1 / 1                     | OK      | OK              | OK       | OK     |
| `lux-crypto-poly-mul`  | OK          | 1 / 3                     | OK      | OK              | OK       | OK     |
| `lux-crypto-ripemd160` | OK          | 5 / 0                     | OK      | OK              | OK       | OK     |
| `lux-crypto-secp256k1` | OK          | 6 / 0                     | OK      | OK              | OK       | OK     |
| `lux-crypto-sha256`    | OK          | 6 / 0                     | OK      | OK              | OK       | OK     |
| `lux-crypto-slhdsa`    | OK          | 2 / 3                     | OK      | OK              | OK       | OK     |

## Summary

- **21 crates** total: 1 umbrella + 20 per-algorithm.
- **All 21 crates** pass `cargo check --release --workspace`.
- **All 21 crates** pass `cargo test --release --workspace` with 0 failures
  (NOTIMPL paths gated `#[ignore]` with FIXME).
- **All 21 crates** generate clean rustdoc with `cargo doc --no-deps`.
- **All 20 per-algorithm crates** pass `cargo publish --dry-run --no-verify`
  (the `lux-crypto` umbrella's dry-run requires its dependencies to already
  exist on crates.io, which they do not yet — see PUBLISHING.md).
- Total: 55 tests pass, 0 fail, 25 ignored (NOTIMPL-gated, will activate as
  C-ABI bodies land).

## Working algorithms (5)

These have a real luxcpp/crypto C-ABI body and a verified spec-vector test
suite that runs by default:

- keccak256 (Ethereum keccak)
- secp256k1 (ecrecover precompile + batch)
- SHA-256 (FIPS 180-4)
- RIPEMD-160 (Bitcoin/Ethereum address derivation)
- BLAKE2b-512 (RFC 7693)

## Wired-but-NOTIMPL algorithms (15)

These have a Rust binding shipping against the canonical C-ABI surface, but
the underlying C-ABI body returns `CRYPTO_ERR_NOTIMPL` (-5). Each crate has
a "binding returns NOTIMPL" guard test that runs by default; spec-vector
roundtrip tests are gated `#[ignore]` with a FIXME pointing at the tracking
issue:

| Crate                 | Tracking issue                |
|-----------------------|-------------------------------|
| lux-crypto-blake3     | `#blake3-c-abi-impl`          |
| lux-crypto-ed25519    | `#ed25519-c-abi-impl`         |
| lux-crypto-slhdsa     | `#slhdsa-c-abi-impl`          |
| lux-crypto-mldsa      | `#mldsa-c-abi-impl`           |
| lux-crypto-mlkem      | `#mlkem-c-abi-impl`           |
| lux-crypto-bls        | `#bls-c-abi-impl`             |
| lux-crypto-kzg        | `#kzg-c-abi-impl`             |
| lux-crypto-bn254      | `#bn254-c-abi-impl`           |
| lux-crypto-aead       | `#aead-c-abi-impl`            |
| lux-crypto-ipa        | `#ipa-c-abi-impl`             |
| lux-crypto-pedersen   | `#pedersen-c-abi-impl`        |
| lux-crypto-lamport    | `#lamport-c-abi-impl`         |
| lux-crypto-ntt        | `#ntt-c-abi-impl`             |
| lux-crypto-poly-mul   | `#poly_mul-c-abi-impl`        |
| lux-crypto-evm256     | `#modexp-c-abi-impl`          |

## Symbol notes

- All C-ABI symbols are brand-neutral; no `lux_` prefix. The legacy `lux_`
  prefix has been removed from `extern "C"` blocks.
- `libsha256.a`, `libripemd160.a`, `libblake2b.a`: hold the C-ABI shim. The
  C++ body is in `lib<alg>_cpu.a` and must also be linked.
- `libsecp256k1.a` holds the `secp256k1_recover` umbrella shim (NOTIMPL for
  sign/verify/sk_to_pk); `libsecp256k1_cpu.a` holds the real
  `secp256k1_ecrecover` body. Both are linked.
- `libkeccak.a` holds the batch shim; `libkeccak_cpu.a` holds the
  `keccak256` body. Both are linked.
- `libevm256.a` and `libpoly_mul.a` are empty placeholder libs in the
  current build layout. The actual symbols are in `libmodexp.a` and
  `libntt.a` respectively; the corresponding crate `build.rs` scripts link
  the parent algorithm's archive.
