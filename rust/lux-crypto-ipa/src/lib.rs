// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ipa: canonical Rust binding for the Lux Banderwagon-IPA
// (Inner Product Argument) C-ABI per EIP-7805 / Verkle.
//
// Operations:
//   ipa_commit              -> Pedersen commit using IPA SRS G_0..G_{n-1}
//   ipa_multiproof_verify   -> full multiproof verifier consuming the
//                              576-byte (D || L[8] || R[8] || A_scalar)
//                              proof bundle and (Cs, ys, zs) public inputs.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ipa_commit(coeffs: *const u8, n: usize, commit: *mut u8) -> c_int;
    fn ipa_multiproof_verify(
        c_s: *const u8,
        ys: *const u8,
        zs: *const u8,
        num_queries: usize,
        proof: *const u8,
    ) -> c_int;
}

/// Length of an IPA commitment (Banderwagon-compressed).
pub const COMMIT_LEN: usize = 32;
/// Length of one coefficient (Fr scalar) in bytes.
pub const COEFF_LEN: usize = 32;
/// Length of one Cs entry (32-byte Banderwagon commit).
pub const CS_ENTRY_LEN: usize = 32;
/// Length of one ys entry (32-byte big-endian Fr).
pub const YS_ENTRY_LEN: usize = 32;
/// Length of one zs entry (1-byte uint8 evaluation point).
pub const ZS_ENTRY_LEN: usize = 1;
/// Length of the IPA multiproof bundle (D || L[8] || R[8] || A_scalar).
pub const PROOF_LEN: usize = 576;
/// Maximum SRS length (matches the Verkle 256-element setup).
pub const MAX_SRS_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    LengthExceeded,
    VerifyFail,
    Internal(c_int),
}

/// Compute the IPA commitment over `coeffs`. Returns the 32-byte
/// Banderwagon-compressed commitment.
pub fn commit(coeffs: &[u8]) -> Result<[u8; COMMIT_LEN], Error> {
    if coeffs.len() % COEFF_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = coeffs.len() / COEFF_LEN;
    if n > MAX_SRS_LEN {
        return Err(Error::LengthExceeded);
    }
    let mut out = [0u8; COMMIT_LEN];
    // SAFETY: lengths checked, pointers valid for the call.
    let rc = unsafe { ipa_commit(coeffs.as_ptr(), n, out.as_mut_ptr()) };
    match rc {
        0 => Ok(out),
        -1 => Err(Error::BadInput),
        -2 => Err(Error::LengthExceeded),
        x => Err(Error::Internal(x)),
    }
}

/// Verify an IPA multiproof. Returns `Ok(())` on success.
pub fn multiproof_verify(
    cs: &[u8],
    ys: &[u8],
    zs: &[u8],
    proof: &[u8; PROOF_LEN],
) -> Result<(), Error> {
    if cs.len() % CS_ENTRY_LEN != 0
        || ys.len() % YS_ENTRY_LEN != 0
        || zs.is_empty()
    {
        return Err(Error::BadInput);
    }
    let n = cs.len() / CS_ENTRY_LEN;
    if ys.len() / YS_ENTRY_LEN != n || zs.len() != n {
        return Err(Error::BadInput);
    }
    // SAFETY: lengths checked.
    let rc = unsafe {
        ipa_multiproof_verify(cs.as_ptr(), ys.as_ptr(), zs.as_ptr(), n, proof.as_ptr())
    };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}
