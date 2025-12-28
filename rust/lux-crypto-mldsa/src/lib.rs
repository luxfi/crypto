// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-mldsa: canonical Rust binding for the Lux ML-DSA C-ABI
// (FIPS 204 / "Module-Lattice-Based Digital Signature Algorithm").
//
// The C-ABI in `luxcpp/crypto/mldsa/c-abi/c_mldsa.cpp` dispatches to the
// vendored PQClean reference. `mode` selects the parameter set:
//
//   2 -> ML-DSA-44  (NIST L2,  pk=1312,  sk=2560,  sig<=2420)
//   3 -> ML-DSA-65  (NIST L3,  pk=1952,  sk=4032,  sig<=3309)
//   5 -> ML-DSA-87  (NIST L5,  pk=2592,  sk=4896,  sig<=4627)

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

/// FIPS 204 parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// ML-DSA-44: NIST security category 2.
    M44,
    /// ML-DSA-65: NIST security category 3.
    M65,
    /// ML-DSA-87: NIST security category 5.
    M87,
}

impl Mode {
    /// FIPS 204 public-key length (bytes).
    pub const fn pk_len(self) -> usize {
        match self {
            Self::M44 => 1312,
            Self::M65 => 1952,
            Self::M87 => 2592,
        }
    }

    /// FIPS 204 secret-key length (bytes).
    pub const fn sk_len(self) -> usize {
        match self {
            Self::M44 => 2560,
            Self::M65 => 4032,
            Self::M87 => 4896,
        }
    }

    /// Maximum signature length (bytes). Actual signatures are at most this
    /// length; PQClean returns the exact length via `sign`.
    pub const fn sig_max(self) -> usize {
        match self {
            Self::M44 => 2420,
            Self::M65 => 3309,
            Self::M87 => 4627,
        }
    }

    fn as_int(self) -> c_int {
        match self {
            Self::M44 => 2,
            Self::M65 => 3,
            Self::M87 => 5,
        }
    }
}

/// Errors returned by ML-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// One of the input buffers was malformed.
    BadInput,
    /// Signature verification failed.
    VerifyFail,
    /// The C-ABI returned an unexpected status.
    Internal(c_int),
}

/// Generate a fresh ML-DSA keypair. The PQClean body uses entropy from the
/// system `randombytes` hook; the seed argument is reserved for forward
/// compatibility with deterministic-keygen variants.
pub fn keygen(mode: Mode) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    let seed = [0u8; 32];
    // SAFETY: Buffers sized to FIPS 204 parameter set; seed is 32 bytes.
    let rc = unsafe {
        mldsa_keygen(
            mode.as_int(),
            seed.as_ptr(),
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
        )
    };
    match rc {
        0 => Ok((pk, sk)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Sign `msg` using the ML-DSA secret key `sk`.
pub fn sign(mode: Mode, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    if sk.len() != mode.sk_len() {
        return Err(Error::BadInput);
    }
    let mut sig = vec![0u8; mode.sig_max()];
    let mut sig_len = sig.len();
    // SAFETY: sk and sig are sized; msg is allowed to be empty (NULL handling
    // is left to the body).
    let rc = unsafe {
        mldsa_sign(
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

/// Verify a signature.
pub fn verify(mode: Mode, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if pk.len() != mode.pk_len() {
        return Err(Error::BadInput);
    }
    // SAFETY: pk sized; msg/sig caller-owned.
    let rc = unsafe {
        mldsa_verify(
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
