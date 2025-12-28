// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ed25519: canonical Rust binding for the Lux Ed25519 C-ABI.
// Conforms to RFC 8032 §5.1 (PureEdDSA over Curve25519, "Ed25519").
//
// Status: luxcpp/crypto/ed25519/c-abi/c_ed25519.cpp returns CRYPTO_ERR_NOTIMPL
// for keygen/sign/verify. Tests gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ed25519_keygen(seed: *const u8, sk: *mut u8, pk: *mut u8) -> c_int;
    fn ed25519_sign(sk: *const u8, msg: *const u8, msg_len: usize, sig: *mut u8) -> c_int;
    fn ed25519_verify(pk: *const u8, msg: *const u8, msg_len: usize, sig: *const u8) -> c_int;
}

pub const SEED_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidSignature,
}

#[inline]
pub fn keygen(seed: &[u8; SEED_LEN]) -> Result<([u8; SECRET_KEY_LEN], [u8; PUBLIC_KEY_LEN]), Error> {
    let mut sk = [0u8; SECRET_KEY_LEN];
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    // SAFETY: pointers valid for the call's duration; output buffers sized exactly.
    let rc = unsafe { ed25519_keygen(seed.as_ptr(), sk.as_mut_ptr(), pk.as_mut_ptr()) };
    match rc { 0 => Ok((sk, pk)), other => Err(Error::InternalError(other)) }
}

#[inline]
pub fn sign(sk: &[u8; SECRET_KEY_LEN], msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    let mut sig = [0u8; SIGNATURE_LEN];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe {
        ed25519_sign(sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr())
    };
    match rc { 0 => Ok(sig), other => Err(Error::InternalError(other)) }
}

#[inline]
pub fn verify(pk: &[u8; PUBLIC_KEY_LEN], msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> Result<(), Error> {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { ed25519_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) };
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidSignature),
        other => Err(Error::InternalError(other)),
    }
}
