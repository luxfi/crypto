// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-mlkem: canonical Rust binding for the Lux ML-KEM C-ABI
// (FIPS 203 / "Module-Lattice-Based Key-Encapsulation Mechanism").
//
// `mode` selects the FIPS 203 parameter set:
//   2 -> ML-KEM-512   (NIST L1)
//   3 -> ML-KEM-768   (NIST L3)
//   5 -> ML-KEM-1024  (NIST L5)

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn mlkem_keygen(mode: c_int, seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn mlkem_encap(mode: c_int, pk: *const u8, ct: *mut u8, ss: *mut u8) -> c_int;
    fn mlkem_decap(mode: c_int, sk: *const u8, ct: *const u8, ss: *mut u8) -> c_int;
}

/// Length of the ML-KEM shared-secret in bytes (always 32 across modes).
pub const SHARED_SECRET_LEN: usize = 32;

/// FIPS 203 parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// ML-KEM-512: NIST security category 1.
    M512,
    /// ML-KEM-768: NIST security category 3.
    M768,
    /// ML-KEM-1024: NIST security category 5.
    M1024,
}

impl Mode {
    /// FIPS 203 public-key length (bytes).
    pub const fn pk_len(self) -> usize {
        match self {
            Self::M512 => 800,
            Self::M768 => 1184,
            Self::M1024 => 1568,
        }
    }

    /// FIPS 203 secret-key length (bytes).
    pub const fn sk_len(self) -> usize {
        match self {
            Self::M512 => 1632,
            Self::M768 => 2400,
            Self::M1024 => 3168,
        }
    }

    /// FIPS 203 ciphertext length (bytes).
    pub const fn ct_len(self) -> usize {
        match self {
            Self::M512 => 768,
            Self::M768 => 1088,
            Self::M1024 => 1568,
        }
    }

    fn as_int(self) -> c_int {
        match self {
            Self::M512 => 2,
            Self::M768 => 3,
            Self::M1024 => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    Internal(c_int),
}

pub fn keygen(mode: Mode) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    let seed = [0u8; 32];
    // SAFETY: All buffers sized to FIPS 203 parameter set.
    let rc = unsafe {
        mlkem_keygen(mode.as_int(), seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
    };
    match rc {
        0 => Ok((pk, sk)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

pub fn encap(mode: Mode, pk: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::BadInput);
    }
    let mut ct = vec![0u8; mode.ct_len()];
    let mut ss = [0u8; SHARED_SECRET_LEN];
    // SAFETY: pk is sized; ct/ss sized to FIPS 203.
    let rc = unsafe {
        mlkem_encap(mode.as_int(), pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr())
    };
    match rc {
        0 => Ok((ct, ss)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

pub fn decap(mode: Mode, sk: &[u8], ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], Error> {
    if sk.len() != mode.sk_len() || ct.len() != mode.ct_len() {
        return Err(Error::BadInput);
    }
    let mut ss = [0u8; SHARED_SECRET_LEN];
    // SAFETY: sk/ct sized; ss sized.
    let rc = unsafe {
        mlkem_decap(mode.as_int(), sk.as_ptr(), ct.as_ptr(), ss.as_mut_ptr())
    };
    match rc {
        0 => Ok(ss),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}
