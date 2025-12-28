// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-slhdsa: canonical Rust binding for Lux SLH-DSA (FIPS 205, the
// final standardized form of SPHINCS+).
//
// Status: luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp returns CRYPTO_ERR_NOTIMPL
// for keygen/sign/verify. Tests gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn slhdsa_keygen(mode: c_int, seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn slhdsa_sign(
        mode: c_int,
        sk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> c_int;
    fn slhdsa_verify(
        mode: c_int,
        pk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> c_int;
}

/// FIPS 205 SLH-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Mode {
    /// SLH-DSA-SHA2-128f (NIST L1).
    Sha2_128f = 2,
    /// SLH-DSA-SHA2-192f (NIST L3).
    Sha2_192f = 3,
    /// SLH-DSA-SHA2-256f (NIST L5).
    Sha2_256f = 5,
}

impl Mode {
    pub const fn pk_len(self) -> usize {
        match self { Mode::Sha2_128f => 32, Mode::Sha2_192f => 48, Mode::Sha2_256f => 64 }
    }
    pub const fn sk_len(self) -> usize {
        match self { Mode::Sha2_128f => 64, Mode::Sha2_192f => 96, Mode::Sha2_256f => 128 }
    }
    pub const fn sig_len(self) -> usize {
        match self { Mode::Sha2_128f => 17088, Mode::Sha2_192f => 35664, Mode::Sha2_256f => 49856 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidSignature,
    InvalidLength,
}

#[inline]
pub fn keygen(mode: Mode, seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || sk.len() != mode.sk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        slhdsa_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

#[inline]
pub fn sign(mode: Mode, sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<usize, Error> {
    if sk.len() != mode.sk_len() || sig.len() < mode.sig_len() {
        return Err(Error::InvalidLength);
    }
    let mut out_len: usize = sig.len();
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        slhdsa_sign(
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

#[inline]
pub fn verify(mode: Mode, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe {
        slhdsa_verify(
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
