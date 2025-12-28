// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-mldsa: canonical Rust binding for Lux ML-DSA (FIPS 204) C-ABI.
//
// Mode encoding matches `luxcpp/crypto/mldsa/c-abi/c_mldsa.cpp`:
//   2 -> ML-DSA-44 (NIST L2)
//   3 -> ML-DSA-65 (NIST L3)
//   5 -> ML-DSA-87 (NIST L5)
//
// Buffer sizes are FIPS 204 fixed.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn mldsa_keygen(mode: c_int, seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn mldsa_sign(
        mode: c_int,
        sk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> c_int;
    fn mldsa_verify(
        mode: c_int,
        pk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> c_int;
}

/// FIPS 204 ML-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Mode {
    /// ML-DSA-44 (NIST Level 2).
    M44 = 2,
    /// ML-DSA-65 (NIST Level 3).
    M65 = 3,
    /// ML-DSA-87 (NIST Level 5).
    M87 = 5,
}

impl Mode {
    /// Public key length for this parameter set (FIPS 204).
    #[inline]
    pub const fn pk_len(self) -> usize {
        match self {
            Mode::M44 => 1312,
            Mode::M65 => 1952,
            Mode::M87 => 2592,
        }
    }
    /// Secret key length for this parameter set (FIPS 204).
    #[inline]
    pub const fn sk_len(self) -> usize {
        match self {
            Mode::M44 => 2560,
            Mode::M65 => 4032,
            Mode::M87 => 4896,
        }
    }
    /// Maximum signature length for this parameter set (FIPS 204).
    #[inline]
    pub const fn sig_len(self) -> usize {
        match self {
            Mode::M44 => 2420,
            Mode::M65 => 3309,
            Mode::M87 => 4627,
        }
    }
}

/// Errors returned by ML-DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
    /// Buffer slice was the wrong size for the requested parameter set.
    InvalidLength,
}

/// Generate a fresh ML-DSA keypair from `seed`.
#[inline]
pub fn keygen(mode: Mode, seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || sk.len() != mode.sk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        mldsa_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::Internal(other)),
    }
}

/// Sign `msg` under `sk`. Returns the produced signature length.
#[inline]
pub fn sign(mode: Mode, sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<usize, Error> {
    if sk.len() != mode.sk_len() || sig.len() < mode.sig_len() {
        return Err(Error::InvalidLength);
    }
    let mut sig_len: usize = sig.len();
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        mldsa_sign(
            mode as c_int,
            sk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            &mut sig_len as *mut usize,
        )
    };
    match rc {
        0 => Ok(sig_len),
        other => Err(Error::Internal(other)),
    }
}

/// Verify an ML-DSA signature.
#[inline]
pub fn verify(mode: Mode, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pk length checked; pointers valid for the call's duration.
    let rc = unsafe {
        mldsa_verify(
            mode as c_int,
            pk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::Internal(other)),
    }
}
