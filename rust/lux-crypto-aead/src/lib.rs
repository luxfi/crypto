// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-aead: canonical Rust binding for Lux ChaCha20-Poly1305 AEAD
// (RFC 8439). Single-shot seal/open with 32-byte key, 12-byte nonce, and
// 16-byte authentication tag.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn aead_chacha20poly1305_seal(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        pt: *const u8,
        pt_len: usize,
        ct: *mut u8,
        tag: *mut u8,
    ) -> c_int;
    fn aead_chacha20poly1305_open(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        ct: *const u8,
        ct_len: usize,
        tag: *const u8,
        pt: *mut u8,
    ) -> c_int;
}

/// Length of a ChaCha20-Poly1305 key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a ChaCha20-Poly1305 nonce in bytes (RFC 8439 IETF construction).
pub const NONCE_LEN: usize = 12;
/// Length of a Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Errors returned by AEAD operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `open` rejected the ciphertext/tag.
    InvalidTag,
    /// Input lengths disagreed.
    LengthMismatch,
}

/// Encrypt-and-authenticate `pt` under `key` with `nonce` and associated data.
///
/// Writes ciphertext to `ct` (must be the same length as `pt`) and the 16-byte
/// authentication tag to `tag`.
#[inline]
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) -> Result<(), Error> {
    if ct.len() != pt.len() {
        return Err(Error::LengthMismatch);
    }
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        aead_chacha20poly1305_seal(
            key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    };
    match rc {
        0 => Ok(()),
        other => Err(Error::Internal(other)),
    }
}

/// Authenticate-and-decrypt `ct` under `key` with `nonce`, `aad`, and `tag`.
///
/// Writes plaintext to `pt` (must be the same length as `ct`).
#[inline]
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    pt: &mut [u8],
) -> Result<(), Error> {
    if pt.len() != ct.len() {
        return Err(Error::LengthMismatch);
    }
    // SAFETY: lengths checked; pointers valid for the call's duration.
    let rc = unsafe {
        aead_chacha20poly1305_open(
            key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            ct.as_ptr(),
            ct.len(),
            tag.as_ptr(),
            pt.as_mut_ptr(),
        )
    };
    match rc {
        0 => Ok(()),
        -3 => Err(Error::InvalidTag),
        other => Err(Error::Internal(other)),
    }
}
