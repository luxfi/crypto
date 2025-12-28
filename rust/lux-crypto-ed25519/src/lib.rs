// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ed25519: canonical Rust binding for the Lux Ed25519 C-ABI.
//
// Links statically against `libed25519.a` and `libed25519_cpu.a` produced by
// `luxcpp/crypto/ed25519`, whose CPU body wraps the vendored ed25519-donna
// reference (Andrew Moon, public domain). Conforms to RFC 8032 §5.1 (PureEdDSA
// over Curve25519, "Ed25519").
//
// The C-ABI uses the canonical 32-byte secret form: `sk` is the 32-byte seed
// (RFC 8032 §5.1.5 "private key"). The expanded 64-byte NaCl form
// (seed || pk) is internal to the C++ wrapper.
//
// All three core operations (`keygen`, `sign`, `verify`) are byte-equal to
// libsodium / ed25519-dalek across the RFC 8032 §7.1 vector set.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ed25519_keygen(seed: *const u8, sk: *mut u8, pk: *mut u8) -> c_int;
    fn ed25519_sign(
        sk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *mut u8,
    ) -> c_int;
    fn ed25519_verify(
        pk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
    ) -> c_int;
}

/// Length of a 32-byte Ed25519 seed (RFC 8032 §5.1.5 "private key").
pub const SEED_LEN: usize = 32;
/// Length of a 32-byte Ed25519 secret key (= seed; canonical form).
pub const SECRET_KEY_LEN: usize = 32;
/// Length of a 32-byte Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a 64-byte Ed25519 signature (R || S, RFC 8032 §5.1.6).
pub const SIGNATURE_LEN: usize = 64;

/// Errors returned by the Ed25519 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
}

/// Derive the (secret_key, public_key) pair from a 32-byte seed.
///
/// `secret_key` is the canonical RFC 8032 form: the 32-byte seed itself.
/// The expanded NaCl 64-byte form (seed || pk) is internal to the C wrapper.
#[inline]
pub fn keygen(seed: &[u8; SEED_LEN]) -> ([u8; SECRET_KEY_LEN], [u8; PUBLIC_KEY_LEN]) {
    let mut sk = [0u8; SECRET_KEY_LEN];
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    // SAFETY: pointers valid for the call's duration; output buffers sized exactly.
    let rc = unsafe { ed25519_keygen(seed.as_ptr(), sk.as_mut_ptr(), pk.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "ed25519_keygen returned non-zero status: {}", rc);
    (sk, pk)
}

/// Sign `msg` under `sk`. The signature is deterministic per RFC 8032 §5.1.6.
#[inline]
pub fn sign(sk: &[u8; SECRET_KEY_LEN], msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut sig = [0u8; SIGNATURE_LEN];
    // SAFETY: pointers valid for the call's duration; sig buffer sized exactly.
    let rc = unsafe {
        ed25519_sign(
            sk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
        )
    };
    debug_assert_eq!(rc, 0, "ed25519_sign returned non-zero status: {}", rc);
    sig
}

/// Verify a single Ed25519 signature.
///
/// Returns `Ok(())` iff the signature is valid for `(pk, msg)`. Returns
/// `Err(Error::InvalidSignature)` when the C-ABI rejects the triple, and
/// `Err(Error::InternalError)` for any other non-zero status.
#[inline]
pub fn verify(
    pk: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe {
        ed25519_verify(
            pk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
        )
    };
    match rc {
        0 => Ok(()),
        // CRYPTO_ERR_VERIFY = -3 in lux_crypto.h
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}
