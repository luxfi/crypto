// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-kzg: canonical Rust binding for Lux KZG point-evaluation C-ABI.
// EIP-4844 surface (precompile 0x0a). Blob length is fixed at 4096 field
// elements * 32 bytes = 131072 bytes; commitment / proof are 48 bytes each
// (compressed BLS12-381 G1).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn kzg_blob_to_commit(blob: *const u8, commit: *mut u8) -> c_int;
    fn kzg_commit_to_proof(blob: *const u8, z: *const u8, proof: *mut u8, y: *mut u8) -> c_int;
    fn kzg_verify_proof(commit: *const u8, z: *const u8, y: *const u8, proof: *const u8) -> c_int;
    fn kzg_verify_blob(blob: *const u8, commit: *const u8, proof: *const u8) -> c_int;
}

/// Length of an EIP-4844 blob in bytes (4096 * 32).
pub const BLOB_LEN: usize = 131_072;
/// Length of a KZG commitment / proof in bytes (compressed BLS12-381 G1).
pub const COMMIT_LEN: usize = 48;
/// Length of a KZG evaluation point / value in bytes (BLS12-381 Fr).
pub const SCALAR_LEN: usize = 32;

/// Errors returned by KZG operations.
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

/// Compute the KZG commitment of `blob`.
#[inline]
pub fn blob_to_commit(blob: &[u8; BLOB_LEN], commit: &mut [u8; COMMIT_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { kzg_blob_to_commit(blob.as_ptr(), commit.as_mut_ptr()) };
    check(rc)
}

/// Compute the KZG proof for `blob` at point `z`, returning `(proof, y)` where
/// `y = polynomial(z)`.
#[inline]
pub fn commit_to_proof(
    blob: &[u8; BLOB_LEN],
    z: &[u8; SCALAR_LEN],
    proof: &mut [u8; COMMIT_LEN],
    y: &mut [u8; SCALAR_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe {
        kzg_commit_to_proof(blob.as_ptr(), z.as_ptr(), proof.as_mut_ptr(), y.as_mut_ptr())
    };
    check(rc)
}

/// Verify a single KZG point-evaluation proof.
#[inline]
pub fn verify_proof(
    commit: &[u8; COMMIT_LEN],
    z: &[u8; SCALAR_LEN],
    y: &[u8; SCALAR_LEN],
    proof: &[u8; COMMIT_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe {
        kzg_verify_proof(commit.as_ptr(), z.as_ptr(), y.as_ptr(), proof.as_ptr())
    };
    check(rc)
}

/// Verify that `commit` is the KZG commitment of `blob`, with `proof`.
#[inline]
pub fn verify_blob(
    blob: &[u8; BLOB_LEN],
    commit: &[u8; COMMIT_LEN],
    proof: &[u8; COMMIT_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { kzg_verify_blob(blob.as_ptr(), commit.as_ptr(), proof.as_ptr()) };
    check(rc)
}
