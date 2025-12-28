// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ipa: canonical Rust binding for Lux IPA (Inner Product Argument)
// commitments and proofs. Used by Verkle trees (Bowe-Grigg-Hopwood IPA over
// Bandersnatch). Conforms to ethereum/research's banderwagon IPA spec.
//
// Status: luxcpp/crypto/ipa/c-abi/c_ipa.cpp returns CRYPTO_ERR_NOTIMPL for
// commit/verify. Tests gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ipa_commit(coeffs: *const u8, n: usize, commit: *mut u8) -> c_int;
    fn ipa_verify(commit: *const u8, proof: *const u8, proof_len: usize) -> c_int;
}

/// Length of an IPA commitment (48-byte BLS12-381 G1, compressed).
pub const COMMIT_LEN: usize = 48;

/// Errors returned by the IPA binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidProof,
}

/// Compute the IPA commitment of a polynomial over BLS12-381 Fr coefficients.
/// `coeffs` is `n * 32` bytes (n field elements, big-endian).
#[inline]
pub fn commit(coeffs: &[u8], n: usize) -> Result<[u8; COMMIT_LEN], Error> {
    let mut out = [0u8; COMMIT_LEN];
    // SAFETY: caller asserts coeffs.len() >= n * 32.
    let rc = unsafe { ipa_commit(coeffs.as_ptr(), n, out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// Verify an IPA proof against the commitment.
#[inline]
pub fn verify(commit: &[u8; COMMIT_LEN], proof: &[u8]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { ipa_verify(commit.as_ptr(), proof.as_ptr(), proof.len()) };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidProof),
        other => Err(Error::InternalError(other)),
    }
}
