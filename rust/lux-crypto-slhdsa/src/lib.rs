// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-slhdsa: canonical Rust binding for the Lux SLH-DSA C-ABI.
//
// Links statically against `libslhdsa.a` and `libslhdsa_cpu.a` produced by
// `luxcpp/crypto/slhdsa`, whose CPU body wraps the vendored PQClean reference
// (sphincs-{sha2,shake}-{128,192,256}f-simple/clean, CC0 / public domain).
// Conforms to NIST FIPS 205 §10 parameter catalogue (six 'f' fast variants).
//
// Mode encoding (byte-equal to luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp):
//   2  -> SLH-DSA-SHA2-128f  (NIST L1)
//   3  -> SLH-DSA-SHA2-192f  (NIST L3)
//   5  -> SLH-DSA-SHA2-256f  (NIST L5)
//   12 -> SLH-DSA-SHAKE-128f (NIST L1)
//   13 -> SLH-DSA-SHAKE-192f (NIST L3)
//   15 -> SLH-DSA-SHAKE-256f (NIST L5)
//
// Buffer sizes are FIPS 205 fixed (identical between SHA2 and SHAKE for the
// same security level):
//   128f : pk=32   sk=64    sig<=17088
//   192f : pk=48   sk=96    sig<=35664
//   256f : pk=64   sk=128   sig<=49856

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

/// FIPS 205 SLH-DSA parameter set. The integer mode codes are byte-equal to
/// the C-ABI dispatch in `luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum Mode {
    /// SLH-DSA-SHA2-128f  (NIST L1, SHA2 family, fast variant).
    Sha2_128f = 2,
    /// SLH-DSA-SHA2-192f  (NIST L3, SHA2 family, fast variant).
    Sha2_192f = 3,
    /// SLH-DSA-SHA2-256f  (NIST L5, SHA2 family, fast variant).
    Sha2_256f = 5,
    /// SLH-DSA-SHAKE-128f (NIST L1, SHAKE family, fast variant).
    Shake_128f = 12,
    /// SLH-DSA-SHAKE-192f (NIST L3, SHAKE family, fast variant).
    Shake_192f = 13,
    /// SLH-DSA-SHAKE-256f (NIST L5, SHAKE family, fast variant).
    Shake_256f = 15,
}

impl Mode {
    /// Public key length for this parameter set (FIPS 205).
    #[inline]
    pub const fn pk_len(self) -> usize {
        match self {
            Mode::Sha2_128f | Mode::Shake_128f => 32,
            Mode::Sha2_192f | Mode::Shake_192f => 48,
            Mode::Sha2_256f | Mode::Shake_256f => 64,
        }
    }

    /// Secret key length for this parameter set (FIPS 205).
    #[inline]
    pub const fn sk_len(self) -> usize {
        match self {
            Mode::Sha2_128f | Mode::Shake_128f => 64,
            Mode::Sha2_192f | Mode::Shake_192f => 96,
            Mode::Sha2_256f | Mode::Shake_256f => 128,
        }
    }

    /// Maximum signature length for this parameter set (FIPS 205).
    #[inline]
    pub const fn sig_len(self) -> usize {
        match self {
            Mode::Sha2_128f | Mode::Shake_128f => 17088,
            Mode::Sha2_192f | Mode::Shake_192f => 35664,
            Mode::Sha2_256f | Mode::Shake_256f => 49856,
        }
    }
}

/// Errors returned by the SLH-DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
    /// Buffer slice was the wrong size for the requested parameter set.
    InvalidLength,
}

/// Generate a fresh keypair for the given parameter set. Entropy comes from
/// the underlying C wrapper's getentropy()-backed randombytes (FIPS 205 keygen
/// is randomized; SLH-DSA itself is *signing*-deterministic per §9.1).
///
/// `pk` and `sk` must be sized exactly to `mode.pk_len()` and `mode.sk_len()`.
#[inline]
pub fn keygen(mode: Mode, pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() || sk.len() != mode.sk_len() {
        return Err(Error::InvalidLength);
    }
    // The C-ABI accepts a 32-byte seed pointer that is currently unused by the
    // PQClean reference (which calls randombytes internally). Pass a dummy.
    let dummy_seed = [0u8; 32];
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        slhdsa_keygen(mode as c_int, dummy_seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::InternalError(other)),
    }
}

/// Sign `msg` under `sk` using the given parameter set.
///
/// Returns the byte length of the produced signature (= `mode.sig_len()` for
/// the deployed 'f' fast variants, where signatures are fixed-size).
///
/// `sig` must have capacity at least `mode.sig_len()`. `sk` must be sized
/// exactly to `mode.sk_len()`.
#[inline]
pub fn sign(mode: Mode, sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<usize, Error> {
    if sk.len() != mode.sk_len() || sig.len() < mode.sig_len() {
        return Err(Error::InvalidLength);
    }
    let mut sig_len: usize = sig.len();
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        slhdsa_sign(
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
        other => Err(Error::InternalError(other)),
    }
}

/// Verify a single SLH-DSA signature.
///
/// Returns `Ok(())` iff the signature is valid for `(pk, msg)`. Returns
/// `Err(Error::InvalidSignature)` when the C-ABI rejects the triple, and
/// `Err(Error::InternalError)` for any other non-zero status.
#[inline]
pub fn verify(mode: Mode, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; pk length checked above.
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
        0 => Ok(()),
        // CRYPTO_ERR_VERIFY = -3 in lux_crypto.h
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}
