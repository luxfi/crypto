// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-mldsa: canonical Rust binding for Lux ML-DSA (FIPS 204, the
// final standardized form of CRYSTALS-Dilithium).
//
// Status: luxcpp/crypto/mldsa/c-abi/c_mldsa.cpp returns CRYPTO_ERR_NOTIMPL
// for keygen/sign/verify. Tests are gated #[ignore] until the C-ABI body
// lands. Mode integers map to FIPS 204 §4 parameter sets (2 = ML-DSA-44,
// 3 = ML-DSA-65, 5 = ML-DSA-87).

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
    /// ML-DSA-44 (NIST L2): pk=1312, sk=2560, sig=2420.
    Mode2 = 2,
    /// ML-DSA-65 (NIST L3): pk=1952, sk=4032, sig=3309.
    Mode3 = 3,
    /// ML-DSA-87 (NIST L5): pk=2592, sk=4896, sig=4627.
    Mode5 = 5,
}

impl Mode {
    /// FIPS 204 public key length in bytes.
    pub const fn pk_len(self) -> usize {
        match self { Mode::Mode2 => 1312, Mode::Mode3 => 1952, Mode::Mode5 => 2592 }
    }
    /// FIPS 204 secret key length in bytes.
    pub const fn sk_len(self) -> usize {
        match self { Mode::Mode2 => 2560, Mode::Mode3 => 4032, Mode::Mode5 => 4896 }
    }
    /// FIPS 204 signature length in bytes.
    pub const fn sig_len(self) -> usize {
        match self { Mode::Mode2 => 2420, Mode::Mode3 => 3309, Mode::Mode5 => 4627 }
    }
}

/// Errors returned by the ML-DSA binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
    /// Buffer slice was the wrong size for the requested parameter set.
    InvalidLength,
}

/// Generate an ML-DSA keypair. `pk` and `sk` must be sized exactly to the
/// requested parameter set's `Mode::pk_len()` and `Mode::sk_len()`.
#[inline]
pub fn keygen(mode: Mode, seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || sk.len() != mode.sk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        mldsa_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// Sign `msg` under `sk` using the given parameter set. Returns the signature
/// length actually written.
#[inline]
pub fn sign(mode: Mode, sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<usize, Error> {
    if sk.len() != mode.sk_len() || sig.len() < mode.sig_len() {
        return Err(Error::InvalidLength);
    }
    let mut out_len: usize = sig.len();
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        mldsa_sign(
            mode as c_int,
            sk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            &mut out_len as *mut usize,
        )
    };
    match rc { 0 => Ok(out_len), other => Err(Error::InternalError(other)) }
}

/// Verify a single ML-DSA signature.
#[inline]
pub fn verify(mode: Mode, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; pk length checked.
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
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}
