// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ipa: canonical Rust binding for Lux inner-product-argument C-ABI.
// Used by Verkle trees over Banderwagon (Bulletproofs-style polynomial
// commitment scheme). Commitments are 48-byte compressed group elements.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ipa_commit(coeffs: *const u8, n: usize, commit: *mut u8) -> c_int;
    fn ipa_verify(commit: *const u8, proof: *const u8, proof_len: usize) -> c_int;
}

/// Length of an IPA commitment in bytes (Banderwagon compressed point).
pub const COMMIT_LEN: usize = 48;

/// Errors returned by IPA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `verify` rejected the proof.
    InvalidProof,
}

#[inline]
fn check(rc: c_int) -> Result<(), Error> {
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidProof),
        other => Err(Error::Internal(other)),
    }
}

/// Compute the IPA commitment of a coefficient vector.
#[inline]
pub fn commit(coeffs: &[u8], commit_out: &mut [u8; COMMIT_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; output sized exactly.
    let rc = unsafe { ipa_commit(coeffs.as_ptr(), coeffs.len(), commit_out.as_mut_ptr()) };
    check(rc)
}

/// Verify an IPA proof against a commitment.
#[inline]
pub fn verify(commit_in: &[u8; COMMIT_LEN], proof: &[u8]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; input sized exactly.
    let rc = unsafe { ipa_verify(commit_in.as_ptr(), proof.as_ptr(), proof.len()) };
    check(rc)
}
