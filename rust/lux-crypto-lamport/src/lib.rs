// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-lamport: canonical Rust binding for Lux Lamport one-time
// signatures C-ABI (LP-2506). Each Lamport keypair signs at most one 32-byte
// message under SHA-256.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn lamport_keygen(seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn lamport_sign(sk: *const u8, msg32: *const u8, sig: *mut u8) -> c_int;
    fn lamport_verify(pk: *const u8, msg32: *const u8, sig: *const u8) -> c_int;
}

/// Length of the seed used to derive a Lamport keypair (bytes).
pub const SEED_LEN: usize = 32;
/// Length of a Lamport public key (bytes): 256 pairs of 32-byte SHA-256 outputs.
pub const PK_LEN: usize = 256 * 2 * 32;
/// Length of a Lamport secret key (bytes): 256 pairs of 32-byte preimages.
pub const SK_LEN: usize = 256 * 2 * 32;
/// Length of a Lamport signature (bytes): 256 selected 32-byte preimages.
pub const SIG_LEN: usize = 256 * 32;
/// Length of a SHA-256 message digest (bytes).
pub const MSG_LEN: usize = 32;

/// Errors returned by Lamport operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
}

/// Generate a Lamport keypair from `seed`.
#[inline]
pub fn keygen(
    seed: &[u8; SEED_LEN],
    pk: &mut [u8; PK_LEN],
    sk: &mut [u8; SK_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { lamport_keygen(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc == 0 { Ok(()) } else { Err(Error::Internal(rc)) }
}

/// Sign a 32-byte message digest using `sk`.
#[inline]
pub fn sign(sk: &[u8; SK_LEN], msg: &[u8; MSG_LEN], sig: &mut [u8; SIG_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { lamport_sign(sk.as_ptr(), msg.as_ptr(), sig.as_mut_ptr()) };
    if rc == 0 { Ok(()) } else { Err(Error::Internal(rc)) }
}

/// Verify a Lamport signature.
#[inline]
pub fn verify(pk: &[u8; PK_LEN], msg: &[u8; MSG_LEN], sig: &[u8; SIG_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { lamport_verify(pk.as_ptr(), msg.as_ptr(), sig.as_ptr()) };
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::Internal(other)),
    }
}
