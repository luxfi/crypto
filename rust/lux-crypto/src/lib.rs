// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto: umbrella crate over the per-algorithm Lux crypto bindings.
//
// Re-exports each `lux-crypto-<alg>` crate behind a Cargo feature so a single
// dependency line can pull in exactly the surface a consumer needs:
//
//     [dependencies]
//     lux-crypto = { version = "0.1", default-features = false, features = ["keccak", "secp256k1"] }
//
// The default feature set covers the four algorithms whose underlying C-ABI
// body is wired and byte-equal to a published reference today:
//
//   * keccak       (Ethereum keccak256)
//   * secp256k1    (Ethereum ecrecover precompile)
//   * sha256       (FIPS 180-4)
//   * ripemd160    (Bitcoin/Ethereum address derivation)
//
// Algorithms whose C-ABI body is currently a `CRYPTO_ERR_NOTIMPL` stub are
// re-exported anyway so downstream code can compile against the canonical
// surface; their tests are gated `#[ignore]` until the body lands. See each
// per-algorithm crate's README for status.
//
// Build expectations:
//   - `CRYPTO_DIR` env var points to the install prefix (`include/`, `lib/`).
//   - Or `CRYPTO_BUILD_DIR` env var points at the cmake build directory.
//   - Default fallback path is `../../../../luxcpp/crypto/build-cto`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "aead")]
pub use lux_crypto_aead as aead;
#[cfg(feature = "blake2b")]
pub use lux_crypto_blake2b as blake2b;
#[cfg(feature = "blake3")]
pub use lux_crypto_blake3 as blake3;
#[cfg(feature = "bls")]
pub use lux_crypto_bls as bls;
#[cfg(feature = "bn254")]
pub use lux_crypto_bn254 as bn254;
#[cfg(feature = "ed25519")]
pub use lux_crypto_ed25519 as ed25519;
#[cfg(feature = "evm256")]
pub use lux_crypto_evm256 as evm256;
#[cfg(feature = "ipa")]
pub use lux_crypto_ipa as ipa;
#[cfg(feature = "keccak")]
pub use lux_crypto_keccak as keccak;
#[cfg(feature = "kzg")]
pub use lux_crypto_kzg as kzg;
#[cfg(feature = "lamport")]
pub use lux_crypto_lamport as lamport;
#[cfg(feature = "mldsa")]
pub use lux_crypto_mldsa as mldsa;
#[cfg(feature = "mlkem")]
pub use lux_crypto_mlkem as mlkem;
#[cfg(feature = "ntt")]
pub use lux_crypto_ntt as ntt;
#[cfg(feature = "pedersen")]
pub use lux_crypto_pedersen as pedersen;
#[cfg(feature = "poly-mul")]
pub use lux_crypto_poly_mul as poly_mul;
#[cfg(feature = "ripemd160")]
pub use lux_crypto_ripemd160 as ripemd160;
#[cfg(feature = "secp256k1")]
pub use lux_crypto_secp256k1 as secp256k1;
#[cfg(feature = "sha256")]
pub use lux_crypto_sha256 as sha256;
#[cfg(feature = "slhdsa")]
pub use lux_crypto_slhdsa as slhdsa;
