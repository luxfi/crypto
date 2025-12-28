// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-poseidon: canonical Rust binding for the Lux Poseidon2 C-ABI.
//
// Links statically against `libposeidon.a` and `libposeidon_cpu.a` produced
// by `luxcpp/crypto/poseidon`, whose CPU body is a first-party port of the
// gnark-crypto v0.20.1 Poseidon2 t=2 BN254 permutation
// (NewParameters(2, 6, 50)) plus the canonical Merkle-Damgard construction
// (NewMerkleDamgardHasher() with 32-byte zero IV).
//
// Byte-equal to upstream gnark-crypto.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    /// Poseidon2 t=2 BN254 Merkle-Damgard hash. Returns 0 on success, or a
    /// negative `CRYPTO_ERR_*` code on failure.
    fn poseidon_bn254(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a Poseidon2 BN254 digest in bytes (one fr.Element).
pub const DIGEST_LEN: usize = 32;

/// Compute the Poseidon2 t=2 BN254 Merkle-Damgard hash of `input`.
///
/// `input` is consumed in 32-byte big-endian fr-blocks. If the final block is
/// shorter than 32 bytes, it is left-padded with zeroes (matching the upstream
/// gnark `cloneLeftPadded` semantics). Each block must encode a value strictly
/// less than the BN254 scalar field modulus `r`; otherwise the call returns
/// the empty zero-IV result and reports a non-zero status via the C-ABI return
/// value (a `debug_assert` in this binding catches that condition during
/// development).
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: pointers are valid for the duration of the call; output is
    // sized to exactly DIGEST_LEN bytes.
    let rc = unsafe { poseidon_bn254(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "poseidon_bn254 returned non-zero status: {}", rc);
    out
}

/// Compute the Poseidon2 t=2 BN254 Merkle-Damgard hash of `input` into a
/// caller-supplied buffer. Returns the same byte slice for ergonomic chaining.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; DIGEST_LEN]) -> &'a [u8; DIGEST_LEN] {
    // SAFETY: pointers are valid for the duration of the call; output is
    // sized to exactly DIGEST_LEN bytes.
    let rc = unsafe { poseidon_bn254(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "poseidon_bn254 returned non-zero status: {}", rc);
    output
}
