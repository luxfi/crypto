// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-mlkem: canonical Rust binding for Lux ML-KEM (FIPS 203) C-ABI.
//
// Mode encoding matches `luxcpp/crypto/mlkem/c-abi/c_mlkem.cpp`:
//   2 -> ML-KEM-512  (NIST L1)
//   3 -> ML-KEM-768  (NIST L3)
//   5 -> ML-KEM-1024 (NIST L5)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn mlkem_keygen(mode: c_int, seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn mlkem_encap(mode: c_int, pk: *const u8, ct: *mut u8, ss: *mut u8) -> c_int;
    fn mlkem_decap(mode: c_int, sk: *const u8, ct: *const u8, ss: *mut u8) -> c_int;
}

/// FIPS 203 ML-KEM parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Mode {
    /// ML-KEM-512 (NIST Level 1).
    K512 = 2,
    /// ML-KEM-768 (NIST Level 3).
    K768 = 3,
    /// ML-KEM-1024 (NIST Level 5).
    K1024 = 5,
}

impl Mode {
    /// Public key length for this parameter set (FIPS 203).
    #[inline]
    pub const fn pk_len(self) -> usize {
        match self {
            Mode::K512 => 800,
            Mode::K768 => 1184,
            Mode::K1024 => 1568,
        }
    }
    /// Secret key length for this parameter set (FIPS 203).
    #[inline]
    pub const fn sk_len(self) -> usize {
        match self {
            Mode::K512 => 1632,
            Mode::K768 => 2400,
            Mode::K1024 => 3168,
        }
    }
    /// Ciphertext length for this parameter set (FIPS 203).
    #[inline]
    pub const fn ct_len(self) -> usize {
        match self {
            Mode::K512 => 768,
            Mode::K768 => 1088,
            Mode::K1024 => 1568,
        }
    }
}

/// Length of the shared secret produced by encap/decap (bytes).
pub const SS_LEN: usize = 32;

/// Errors returned by ML-KEM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// Buffer slice was the wrong size for the requested parameter set.
    InvalidLength,
}

/// Generate an ML-KEM keypair from `seed`.
#[inline]
pub fn keygen(mode: Mode, seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || sk.len() != mode.sk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        mlkem_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::Internal(other)),
    }
}

/// Encapsulate a fresh shared secret to a public key.
#[inline]
pub fn encap(mode: Mode, pk: &[u8], ct: &mut [u8], ss: &mut [u8; SS_LEN]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || ct.len() != mode.ct_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        mlkem_encap(mode as c_int, pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr())
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::Internal(other)),
    }
}

/// Decapsulate a ciphertext under `sk` to recover the shared secret.
#[inline]
pub fn decap(mode: Mode, sk: &[u8], ct: &[u8], ss: &mut [u8; SS_LEN]) -> Result<(), Error> {
    if sk.len() != mode.sk_len() || ct.len() != mode.ct_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        mlkem_decap(mode as c_int, sk.as_ptr(), ct.as_ptr(), ss.as_mut_ptr())
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::Internal(other)),
    }
}
