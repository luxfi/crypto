// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-kzg: canonical Rust binding for the Lux KZG C-ABI per EIP-4844.
//
// Operations exposed:
//   kzg_verify_proof    — point-evaluation precompile (0x0a). REAL in this
//                         build: backed by the first-party body in
//                         luxcpp/crypto/kzg/cpp/kzg.cpp using BLS12-381
//                         pairings with hard-coded [s]_2; no 4096-element
//                         trusted setup needed.
//   kzg_blob_to_commit  — blob -> 48-byte commitment. NOT WIRED in this
//                         build; the body lives in c_kzg_blob.cpp and is
//                         in a separate TU that is not included in
//                         libkzg.a/libkzg_cpu.a today. Returns NOTIMPL.
//   kzg_commit_to_proof — same as above; NOT WIRED.
//   kzg_verify_blob     — same as above; NOT WIRED.
//
// The blob-op surface is exposed in this crate's API for forward
// compatibility — once luxcpp/crypto wires the c_kzg_blob TU into the
// archive, no Rust changes are needed. Callers should expect
// `Error::Internal(-5)` on those ops in the current build.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn kzg_blob_to_commit(blob: *const u8, commit: *mut u8) -> c_int;
    fn kzg_commit_to_proof(
        blob: *const u8,
        z: *const u8,
        proof: *mut u8,
        y: *mut u8,
    ) -> c_int;
    fn kzg_verify_proof(
        commit: *const u8,
        z: *const u8,
        y: *const u8,
        proof: *const u8,
    ) -> c_int;
    fn kzg_verify_blob(blob: *const u8, commit: *const u8, proof: *const u8) -> c_int;
}

/// Length of an EIP-4844 blob (4096 32-byte field elements).
pub const BLOB_LEN: usize = 131072;
/// Length of a KZG commitment (G1 element, 48 bytes compressed).
pub const COMMIT_LEN: usize = 48;
/// Length of a KZG proof (G1 element, 48 bytes compressed).
pub const PROOF_LEN: usize = 48;
/// Length of an Fr scalar input (z, y) in bytes.
pub const SCALAR_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    VerifyFail,
    Internal(c_int),
}

/// Convert a 131072-byte blob to its 48-byte KZG commitment.
pub fn blob_to_commit(blob: &[u8; BLOB_LEN]) -> Result<[u8; COMMIT_LEN], Error> {
    let mut commit = [0u8; COMMIT_LEN];
    // SAFETY: blob and commit sized to spec.
    let rc = unsafe { kzg_blob_to_commit(blob.as_ptr(), commit.as_mut_ptr()) };
    match rc {
        0 => Ok(commit),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Compute a KZG point-evaluation opening: (proof, y) = open(blob, z).
pub fn commit_to_proof(
    blob: &[u8; BLOB_LEN],
    z: &[u8; SCALAR_LEN],
) -> Result<([u8; PROOF_LEN], [u8; SCALAR_LEN]), Error> {
    let mut proof = [0u8; PROOF_LEN];
    let mut y = [0u8; SCALAR_LEN];
    // SAFETY: pointers sized to spec.
    let rc = unsafe {
        kzg_commit_to_proof(blob.as_ptr(), z.as_ptr(), proof.as_mut_ptr(), y.as_mut_ptr())
    };
    match rc {
        0 => Ok((proof, y)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Verify a KZG point-evaluation proof. Returns `Ok(())` if the pairing
/// check passes, `Err(VerifyFail)` if it fails.
pub fn verify_proof(
    commit: &[u8; COMMIT_LEN],
    z: &[u8; SCALAR_LEN],
    y: &[u8; SCALAR_LEN],
    proof: &[u8; PROOF_LEN],
) -> Result<(), Error> {
    // SAFETY: All inputs sized to spec.
    let rc = unsafe {
        kzg_verify_proof(commit.as_ptr(), z.as_ptr(), y.as_ptr(), proof.as_ptr())
    };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}

/// Verify a KZG blob proof: checks that the blob commits to the given
/// commitment and the proof is valid for that commitment.
pub fn verify_blob(
    blob: &[u8; BLOB_LEN],
    commit: &[u8; COMMIT_LEN],
    proof: &[u8; PROOF_LEN],
) -> Result<(), Error> {
    // SAFETY: All inputs sized to spec.
    let rc = unsafe { kzg_verify_blob(blob.as_ptr(), commit.as_ptr(), proof.as_ptr()) };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}
