// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-mlkem: canonical Rust binding for Lux ML-KEM (FIPS 203, the
// final standardized form of CRYSTALS-Kyber).
//
// Status: luxcpp/crypto/mlkem/c-abi/c_mlkem.cpp returns CRYPTO_ERR_NOTIMPL
// for keygen/encap/decap. Tests are gated #[ignore] until the C-ABI body
// lands. Mode integers map to FIPS 203 §4 parameter sets (2 = ML-KEM-512,
// 3 = ML-KEM-768, 5 = ML-KEM-1024).

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
    /// ML-KEM-512 (NIST L1): pk=800, sk=1632, ct=768.
    Mode2 = 2,
    /// ML-KEM-768 (NIST L3): pk=1184, sk=2400, ct=1088.
    Mode3 = 3,
    /// ML-KEM-1024 (NIST L5): pk=1568, sk=3168, ct=1568.
    Mode5 = 5,
}

impl Mode {
    /// FIPS 203 public key length in bytes.
    pub const fn pk_len(self) -> usize {
        match self { Mode::Mode2 => 800, Mode::Mode3 => 1184, Mode::Mode5 => 1568 }
    }
    /// FIPS 203 secret key length in bytes.
    pub const fn sk_len(self) -> usize {
        match self { Mode::Mode2 => 1632, Mode::Mode3 => 2400, Mode::Mode5 => 3168 }
    }
    /// FIPS 203 ciphertext length in bytes.
    pub const fn ct_len(self) -> usize {
        match self { Mode::Mode2 => 768, Mode::Mode3 => 1088, Mode::Mode5 => 1568 }
    }
}

/// Length of the shared secret (32 bytes, FIPS 203 §6).
pub const SS_LEN: usize = 32;

/// Errors returned by the ML-KEM binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidLength,
}

/// Generate an ML-KEM keypair from a 32-byte seed.
#[inline]
pub fn keygen(mode: Mode, seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || sk.len() != mode.sk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        mlkem_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// Encapsulate against a public key. Writes the ciphertext into `ct` and the
/// 32-byte shared secret into `ss`.
#[inline]
pub fn encap(mode: Mode, pk: &[u8], ct: &mut [u8], ss: &mut [u8; SS_LEN]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || ct.len() != mode.ct_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        mlkem_encap(mode as c_int, pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr())
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// Decapsulate a ciphertext with the secret key. Writes the 32-byte shared
/// secret into `ss`.
#[inline]
pub fn decap(mode: Mode, sk: &[u8], ct: &[u8], ss: &mut [u8; SS_LEN]) -> Result<(), Error> {
    if sk.len() != mode.sk_len() || ct.len() != mode.ct_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        mlkem_decap(mode as c_int, sk.as_ptr(), ct.as_ptr(), ss.as_mut_ptr())
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}
