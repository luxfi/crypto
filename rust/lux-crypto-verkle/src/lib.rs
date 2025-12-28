// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-verkle: canonical Rust binding for the Lux Verkle C-ABI.
//
//   verkle_commit              -> MSM over Verkle SRS (256 G_i).
//   verkle_multiproof_verify   -> alias of ipa_multiproof_verify.
//
// The Verkle proof format IS an IPA multiproof; this crate's verifier is
// byte-equal to the ipa crate's `multiproof_verify`.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn verkle_commit(coeffs: *const u8, n: usize, commit: *mut u8) -> c_int;
    fn verkle_multiproof_verify(
        c_s: *const u8,
        ys: *const u8,
        zs: *const u8,
        num_queries: usize,
        proof: *const u8,
    ) -> c_int;
}

/// Length of the Verkle commitment (Banderwagon-compressed).
pub const COMMIT_LEN: usize = 32;
/// Length of one coefficient in bytes (Fr scalar).
pub const COEFF_LEN: usize = 32;
/// Length of the multiproof bundle.
pub const PROOF_LEN: usize = 576;
/// Maximum SRS length (Verkle: 256-element setup).
pub const MAX_SRS_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    LengthExceeded,
    VerifyFail,
    Internal(c_int),
}

/// Compute the Verkle commitment over `coeffs` (each 32 bytes, n <= 256).
pub fn commit(coeffs: &[u8]) -> Result<[u8; COMMIT_LEN], Error> {
    if coeffs.len() % COEFF_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = coeffs.len() / COEFF_LEN;
    if n > MAX_SRS_LEN {
        return Err(Error::LengthExceeded);
    }
    let mut out = [0u8; COMMIT_LEN];
    // SAFETY: lengths checked.
    let rc = unsafe { verkle_commit(coeffs.as_ptr(), n, out.as_mut_ptr()) };
    match rc {
        0 => Ok(out),
        -1 => Err(Error::BadInput),
        -2 => Err(Error::LengthExceeded),
        x => Err(Error::Internal(x)),
    }
}

/// Verify a Verkle multiproof.
pub fn multiproof_verify(
    cs: &[u8],
    ys: &[u8],
    zs: &[u8],
    proof: &[u8; PROOF_LEN],
) -> Result<(), Error> {
    if cs.len() % 32 != 0 || ys.len() % 32 != 0 || zs.is_empty() {
        return Err(Error::BadInput);
    }
    let n = cs.len() / 32;
    if ys.len() / 32 != n || zs.len() != n {
        return Err(Error::BadInput);
    }
    // SAFETY: lengths checked.
    let rc = unsafe {
        verkle_multiproof_verify(cs.as_ptr(), ys.as_ptr(), zs.as_ptr(), n, proof.as_ptr())
    };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}
