// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-bls: canonical Rust binding for Lux BLS12-381 signature C-ABI.
// Links the canonical CPU body in `luxcpp/crypto/bls`. Mirrors the consensus
// signing surface (sk_to_pk / sign / verify / aggregate / batch_verify).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn bls_keygen(seed: *const u8, sk: *mut u8) -> c_int;
    fn bls_sk_to_pk(sk: *const u8, pk: *mut u8) -> c_int;
    fn bls_sign(sk: *const u8, msg: *const u8, msg_len: usize, sig: *mut u8) -> c_int;
    fn bls_verify(pk: *const u8, msg: *const u8, msg_len: usize, sig: *const u8) -> c_int;
    fn bls_aggregate_pubkeys(pks: *const u8, n: usize, agg_pk: *mut u8) -> c_int;
    fn bls_aggregate_sigs(sigs: *const u8, n: usize, agg_sig: *mut u8) -> c_int;
    fn bls_batch_verify(
        pks: *const u8,
        msgs: *const u8,
        msg_len: usize,
        sigs: *const u8,
        n: usize,
    ) -> c_int;
}

/// Length of a BLS12-381 secret key (Fr scalar, big-endian) in bytes.
pub const SK_LEN: usize = 32;
/// Length of a compressed BLS12-381 G1 public key in bytes.
pub const PK_LEN: usize = 48;
/// Length of a compressed BLS12-381 G2 signature in bytes.
pub const SIG_LEN: usize = 96;
/// Length of the keygen seed in bytes.
pub const SEED_LEN: usize = 32;

/// Errors returned by BLS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
}

#[inline]
fn check(rc: c_int) -> Result<(), Error> {
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::Internal(other)),
    }
}

/// Derive a secret key from a 32-byte seed.
#[inline]
pub fn keygen(seed: &[u8; SEED_LEN], sk: &mut [u8; SK_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { bls_keygen(seed.as_ptr(), sk.as_mut_ptr()) };
    check(rc)
}

/// Compute the compressed public key for a secret key.
#[inline]
pub fn sk_to_pk(sk: &[u8; SK_LEN], pk: &mut [u8; PK_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { bls_sk_to_pk(sk.as_ptr(), pk.as_mut_ptr()) };
    check(rc)
}

/// Sign a message under `sk`.
#[inline]
pub fn sign(sk: &[u8; SK_LEN], msg: &[u8], sig: &mut [u8; SIG_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { bls_sign(sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()) };
    check(rc)
}

/// Verify a single BLS signature.
#[inline]
pub fn verify(pk: &[u8; PK_LEN], msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { bls_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) };
    check(rc)
}

/// Aggregate `n` compressed public keys into a single public key.
///
/// `pks` must be exactly `n * PK_LEN` bytes.
#[inline]
pub fn aggregate_pubkeys(pks: &[u8], n: usize, agg_pk: &mut [u8; PK_LEN]) -> Result<(), Error> {
    if pks.len() != n * PK_LEN {
        return Err(Error::Internal(-1));
    }
    // SAFETY: buffer length checked; pointers valid for the call's duration.
    let rc = unsafe { bls_aggregate_pubkeys(pks.as_ptr(), n, agg_pk.as_mut_ptr()) };
    check(rc)
}

/// Aggregate `n` compressed signatures into a single signature.
///
/// `sigs` must be exactly `n * SIG_LEN` bytes.
#[inline]
pub fn aggregate_sigs(sigs: &[u8], n: usize, agg_sig: &mut [u8; SIG_LEN]) -> Result<(), Error> {
    if sigs.len() != n * SIG_LEN {
        return Err(Error::Internal(-1));
    }
    // SAFETY: buffer length checked; pointers valid for the call's duration.
    let rc = unsafe { bls_aggregate_sigs(sigs.as_ptr(), n, agg_sig.as_mut_ptr()) };
    check(rc)
}

/// Batch verify `n` (pk, msg, sig) triples sharing a common message length.
#[inline]
pub fn batch_verify(
    pks: &[u8],
    msgs: &[u8],
    msg_len: usize,
    sigs: &[u8],
    n: usize,
) -> Result<(), Error> {
    if pks.len() != n * PK_LEN || sigs.len() != n * SIG_LEN || msgs.len() != n * msg_len {
        return Err(Error::Internal(-1));
    }
    // SAFETY: buffer lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        bls_batch_verify(pks.as_ptr(), msgs.as_ptr(), msg_len, sigs.as_ptr(), n)
    };
    check(rc)
}
