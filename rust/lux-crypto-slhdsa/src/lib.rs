// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-slhdsa: canonical Rust binding for the Lux SLH-DSA C-ABI
// (FIPS 205 / "Stateless Hash-Based Digital Signature Algorithm").
//
// Only the 'fast' (f) parameter sets are wired in this initial port. The 's'
// (small) variants are also FIPS-defined but not yet exposed by the C-ABI.

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

/// FIPS 205 SLH-DSA parameter sets exposed by the C-ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// SHA2-128f: NIST L1.
    Sha2_128F,
    /// SHA2-192f: NIST L3.
    Sha2_192F,
    /// SHA2-256f: NIST L5.
    Sha2_256F,
    /// SHAKE-128f: NIST L1.
    Shake128F,
    /// SHAKE-192f: NIST L3.
    Shake192F,
    /// SHAKE-256f: NIST L5.
    Shake256F,
}

impl Mode {
    /// FIPS 205 public-key length (bytes).
    pub const fn pk_len(self) -> usize {
        match self {
            Self::Sha2_128F | Self::Shake128F => 32,
            Self::Sha2_192F | Self::Shake192F => 48,
            Self::Sha2_256F | Self::Shake256F => 64,
        }
    }

    /// FIPS 205 secret-key length (bytes).
    pub const fn sk_len(self) -> usize {
        match self {
            Self::Sha2_128F | Self::Shake128F => 64,
            Self::Sha2_192F | Self::Shake192F => 96,
            Self::Sha2_256F | Self::Shake256F => 128,
        }
    }

    /// FIPS 205 signature length (bytes).
    pub const fn sig_max(self) -> usize {
        match self {
            Self::Sha2_128F | Self::Shake128F => 17088,
            Self::Sha2_192F | Self::Shake192F => 35664,
            Self::Sha2_256F | Self::Shake256F => 49856,
        }
    }

    fn as_int(self) -> c_int {
        match self {
            Self::Sha2_128F => 2,
            Self::Sha2_192F => 3,
            Self::Sha2_256F => 5,
            Self::Shake128F => 12,
            Self::Shake192F => 13,
            Self::Shake256F => 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    VerifyFail,
    Internal(c_int),
}

pub fn keygen(mode: Mode) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    let seed = [0u8; 32];
    // SAFETY: Buffers sized to FIPS 205 parameter set.
    let rc = unsafe {
        slhdsa_keygen(mode.as_int(), seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc {
        0 => Ok((pk, sk)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

pub fn sign(mode: Mode, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    if sk.len() != mode.sk_len() {
        return Err(Error::BadInput);
    }
    let mut sig = vec![0u8; mode.sig_max()];
    let mut sig_len = sig.len();
    // SAFETY: sk and sig sized to parameter set.
    let rc = unsafe {
        slhdsa_sign(
            mode.as_int(),
            sk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            &mut sig_len,
        )
    };
    match rc {
        0 => {
            sig.truncate(sig_len);
            Ok(sig)
        }
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

pub fn verify(mode: Mode, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::BadInput);
    }
    // SAFETY: pk sized; msg/sig caller-owned.
    let rc = unsafe {
        slhdsa_verify(
            mode.as_int(),
            pk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}
