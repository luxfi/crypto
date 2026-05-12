// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-lamport: canonical Rust binding for the Lux Lamport one-time
// signature C-ABI. Lamport, "Constructing Digital Signatures from a One Way
// Function" (1979), the original hash-based OTS scheme. Used in Lux for
// quantum-resistant validator messages (LP-2506).
//
// Status: luxcpp/crypto/lamport/c-abi/c_lamport.cpp returns CRYPTO_ERR_NOTIMPL
// for keygen / sign / verify. The Rust binding ships against the canonical
// surface; tests are gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn lamport_keygen(seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn lamport_sign(sk: *const u8, msg32: *const u8, sig: *mut u8) -> c_int;
    fn lamport_verify(pk: *const u8, msg32: *const u8, sig: *const u8) -> c_int;
}

/// Length in bytes of the deterministic key-derivation seed.
pub const SEED_LEN: usize = 32;
/// Length in bytes of the message digest signed (SHA-256 width).
pub const MSG_LEN: usize = 32;
/// SHA-256 output width — the per-bit preimage size.
const HASH_SIZE: usize = 32;
/// Number of message bits (also the number of preimage pairs in sk).
const MSG_BITS: usize = MSG_LEN * 8;
/// Lamport secret-key length: 2 preimages × MSG_BITS × HASH_SIZE = 16384.
pub const SK_LEN: usize = MSG_BITS * 2 * HASH_SIZE;
/// Lamport public-key length: 2 sha256 commitments × MSG_BITS × HASH_SIZE = 16384.
pub const PK_LEN: usize = MSG_BITS * 2 * HASH_SIZE;
/// Lamport signature length: 1 preimage per message bit × HASH_SIZE = 8192.
pub const SIG_LEN: usize = MSG_BITS * HASH_SIZE;

/// Errors returned by the Lamport binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
}

/// Generate a Lamport keypair from a 32-byte seed. `pk` and `sk` must be
/// sized to the implementation-defined Lamport parameter set (Hanzo's choice
/// is 32-byte-message Lamport: pk=`32 * 256 * 2 / 8 = 2048` bytes, similarly
/// for sk). The exact lengths are documented in the C-ABI body once it lands.
#[inline]
pub fn keygen(seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { lamport_keygen(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) };
    match rc {
        0 => Ok(()),
        other => Err(Error::InternalError(other)),
    }
}

/// Sign a 32-byte message digest under `sk`. `sig` must be sized to the
/// implementation-defined Lamport signature length.
#[inline]
pub fn sign(sk: &[u8], msg32: &[u8; 32], sig: &mut [u8]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { lamport_sign(sk.as_ptr(), msg32.as_ptr(), sig.as_mut_ptr()) };
    match rc {
        0 => Ok(()),
        other => Err(Error::InternalError(other)),
    }
}

/// Verify a Lamport signature.
#[inline]
pub fn verify(pk: &[u8], msg32: &[u8; 32], sig: &[u8]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { lamport_verify(pk.as_ptr(), msg32.as_ptr(), sig.as_ptr()) };
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}
