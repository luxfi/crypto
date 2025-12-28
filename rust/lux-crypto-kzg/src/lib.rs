// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-kzg: canonical Rust binding for the Lux KZG polynomial-commitment
// C-ABI. Conforms to EIP-4844 ("Shard Blob Transactions") which fixes the blob
// shape at 128 KiB (4096 32-byte field elements) and 48-byte BLS12-381 G1
// commitments / proofs.
//
// Status: luxcpp/crypto/kzg/c-abi/c_kzg.cpp returns CRYPTO_ERR_NOTIMPL for all
// entry points. Tests are gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn kzg_blob_to_commit(blob: *const u8, commit: *mut u8) -> c_int;
    fn kzg_commit_to_proof(blob: *const u8, z: *const u8, proof: *mut u8, y: *mut u8) -> c_int;
    fn kzg_verify_proof(commit: *const u8, z: *const u8, y: *const u8, proof: *const u8) -> c_int;
    fn kzg_verify_blob(blob: *const u8, commit: *const u8, proof: *const u8) -> c_int;
}

/// EIP-4844 blob length (128 KiB = 4096 * 32 bytes).
pub const BLOB_LEN: usize = 131072;
/// 48-byte BLS12-381 G1 commitment (compressed).
pub const COMMIT_LEN: usize = 48;
/// 48-byte BLS12-381 G1 proof (compressed).
pub const PROOF_LEN: usize = 48;
/// 32-byte BLS12-381 Fr field element.
pub const SCALAR_LEN: usize = 32;

/// Errors returned by the KZG binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
    /// Verification rejected the proof.
    InvalidProof,
}

/// Compute the KZG commitment for a 128-KiB blob.
#[inline]
pub fn blob_to_commit(blob: &[u8; BLOB_LEN]) -> Result<[u8; COMMIT_LEN], Error> {
    let mut out = [0u8; COMMIT_LEN];
    // SAFETY: pointers valid for the call's duration; lengths fixed by EIP-4844.
    let rc = unsafe { kzg_blob_to_commit(blob.as_ptr(), out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// Compute the KZG opening proof for `blob` at point `z`. Returns `(proof, y)`
/// where `y = blob_polynomial(z)`.
#[inline]
pub fn commit_to_proof(
    blob: &[u8; BLOB_LEN],
    z: &[u8; SCALAR_LEN],
) -> Result<([u8; PROOF_LEN], [u8; SCALAR_LEN]), Error> {
    let mut proof = [0u8; PROOF_LEN];
    let mut y = [0u8; SCALAR_LEN];
    // SAFETY: pointers valid for the call's duration; output sized exactly.
    let rc = unsafe {
        kzg_commit_to_proof(blob.as_ptr(), z.as_ptr(), proof.as_mut_ptr(), y.as_mut_ptr())
    };
    match rc { 0 => Ok((proof, y)), other => Err(Error::InternalError(other)) }
}

/// Verify a KZG opening proof.
#[inline]
pub fn verify_proof(
    commit: &[u8; COMMIT_LEN],
    z: &[u8; SCALAR_LEN],
    y: &[u8; SCALAR_LEN],
    proof: &[u8; PROOF_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; lengths fixed by EIP-4844.
    let rc = unsafe { kzg_verify_proof(commit.as_ptr(), z.as_ptr(), y.as_ptr(), proof.as_ptr()) };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidProof),
        other => Err(Error::InternalError(other)),
    }
}

/// Verify a blob KZG proof (the EIP-4844 commitment-to-blob check).
#[inline]
pub fn verify_blob(
    blob: &[u8; BLOB_LEN],
    commit: &[u8; COMMIT_LEN],
    proof: &[u8; PROOF_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { kzg_verify_blob(blob.as_ptr(), commit.as_ptr(), proof.as_ptr()) };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidProof),
        other => Err(Error::InternalError(other)),
    }
}
