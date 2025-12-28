// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-pedersen: canonical Rust binding for Lux Pedersen vector
// commitments C-ABI. Commitments are 33-byte compressed group elements
// (Banderwagon).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn pedersen_commit(
        values: *const u8,
        n: usize,
        blinding: *const u8,
        commit: *mut u8,
    ) -> c_int;
    fn pedersen_verify(
        commit: *const u8,
        values: *const u8,
        n: usize,
        blinding: *const u8,
    ) -> c_int;
}

/// Length of a Pedersen blinding factor in bytes.
pub const BLINDING_LEN: usize = 32;
/// Length of a Pedersen commitment in bytes (compressed group element).
pub const COMMIT_LEN: usize = 33;

/// Errors returned by Pedersen operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `verify` rejected the (commit, values, blinding) triple.
    InvalidCommitment,
}

/// Compute a Pedersen commitment to `values` with `blinding`.
#[inline]
pub fn commit(
    values: &[u8],
    blinding: &[u8; BLINDING_LEN],
    commit_out: &mut [u8; COMMIT_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; output sized exactly.
    let rc = unsafe {
        pedersen_commit(
            values.as_ptr(),
            values.len(),
            blinding.as_ptr(),
            commit_out.as_mut_ptr(),
        )
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::Internal(other)),
    }
}

/// Verify that `commit_in` is a Pedersen commitment to `values` with `blinding`.
#[inline]
pub fn verify(
    commit_in: &[u8; COMMIT_LEN],
    values: &[u8],
    blinding: &[u8; BLINDING_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; sizes are exact.
    let rc = unsafe {
        pedersen_verify(
            commit_in.as_ptr(),
            values.as_ptr(),
            values.len(),
            blinding.as_ptr(),
        )
    };
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidCommitment),
        other => Err(Error::Internal(other)),
    }
}
