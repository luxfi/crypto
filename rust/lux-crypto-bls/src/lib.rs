// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-bls: canonical Rust binding for the Lux BLS12-381 signature
// C-ABI. Conforms to draft-irtf-cfrg-bls-signature-05 (BLS Signatures over
// BLS12-381, "min_pk" variant: 48-byte public key, 96-byte signature).
//
// Status: luxcpp/crypto/bls/c-abi/c_bls.cpp returns CRYPTO_ERR_NOTIMPL for
// all entry points. Tests are gated #[ignore] until the C-ABI body lands.

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
    fn bls_aggregate_verify(
        pks: *const u8,
        msg: *const u8,
        msg_len: usize,
        agg_sig: *const u8,
        n: usize,
    ) -> c_int;
    fn bls_batch_verify(
        pks: *const u8,
        msgs: *const u8,
        msg_len: usize,
        sigs: *const u8,
        n: usize,
    ) -> c_int;
}

/// Length of a BLS12-381 secret key.
pub const SK_LEN: usize = 32;
/// Length of a BLS12-381 G1 public key (compressed; "min_pk" variant).
pub const PK_LEN: usize = 48;
/// Length of a BLS12-381 G2 signature (compressed; "min_pk" variant).
pub const SIG_LEN: usize = 96;

/// Errors returned by the BLS binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
    /// `verify` rejected the (msg, sig, pk) triple.
    InvalidSignature,
}

/// Generate a BLS secret key from a 32-byte seed (RFC 9380 / EIP-2333 KDF).
#[inline]
pub fn keygen(seed: &[u8; 32]) -> Result<[u8; SK_LEN], Error> {
    let mut sk = [0u8; SK_LEN];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { bls_keygen(seed.as_ptr(), sk.as_mut_ptr()) };
    match rc { 0 => Ok(sk), other => Err(Error::InternalError(other)) }
}

/// Derive a 48-byte BLS public key from a 32-byte secret key.
#[inline]
pub fn sk_to_pk(sk: &[u8; SK_LEN]) -> Result<[u8; PK_LEN], Error> {
    let mut pk = [0u8; PK_LEN];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { bls_sk_to_pk(sk.as_ptr(), pk.as_mut_ptr()) };
    match rc { 0 => Ok(pk), other => Err(Error::InternalError(other)) }
}

/// Sign `msg` under `sk`. Produces a 96-byte BLS G2 signature.
#[inline]
pub fn sign(sk: &[u8; SK_LEN], msg: &[u8]) -> Result<[u8; SIG_LEN], Error> {
    let mut sig = [0u8; SIG_LEN];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { bls_sign(sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()) };
    match rc { 0 => Ok(sig), other => Err(Error::InternalError(other)) }
}

/// Verify a single BLS signature. Returns `Ok(())` on valid.
#[inline]
pub fn verify(pk: &[u8; PK_LEN], msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { bls_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}

/// Aggregate `n` BLS public keys (each `PK_LEN` bytes, concatenated in `pks`)
/// into a single 48-byte aggregate public key.
#[inline]
pub fn aggregate_pubkeys(pks: &[u8], n: usize) -> Result<[u8; PK_LEN], Error> {
    let mut out = [0u8; PK_LEN];
    // SAFETY: caller asserts pks.len() >= n * PK_LEN.
    let rc = unsafe { bls_aggregate_pubkeys(pks.as_ptr(), n, out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// Aggregate `n` BLS signatures (each `SIG_LEN` bytes, concatenated in `sigs`)
/// into a single 96-byte aggregate signature.
#[inline]
pub fn aggregate_sigs(sigs: &[u8], n: usize) -> Result<[u8; SIG_LEN], Error> {
    let mut out = [0u8; SIG_LEN];
    // SAFETY: caller asserts sigs.len() >= n * SIG_LEN.
    let rc = unsafe { bls_aggregate_sigs(sigs.as_ptr(), n, out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// Verify an aggregate signature over `n` public keys signing the same `msg`.
#[inline]
pub fn aggregate_verify(
    pks: &[u8],
    msg: &[u8],
    agg_sig: &[u8; SIG_LEN],
    n: usize,
) -> Result<(), Error> {
    // SAFETY: caller asserts pks.len() >= n * PK_LEN.
    let rc = unsafe {
        bls_aggregate_verify(pks.as_ptr(), msg.as_ptr(), msg.len(), agg_sig.as_ptr(), n)
    };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}

/// Batch verify `n` distinct (pk, msg, sig) triples, where every msg has the
/// same length `msg_len`.
#[inline]
pub fn batch_verify(pks: &[u8], msgs: &[u8], msg_len: usize, sigs: &[u8], n: usize) -> Result<(), Error> {
    // SAFETY: caller asserts buffer sizes match `n` and `msg_len`.
    let rc = unsafe {
        bls_batch_verify(pks.as_ptr(), msgs.as_ptr(), msg_len, sigs.as_ptr(), n)
    };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}
