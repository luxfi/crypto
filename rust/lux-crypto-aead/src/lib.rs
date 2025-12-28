// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-aead: canonical Rust binding for the Lux ChaCha20-Poly1305 AEAD
// C-ABI. Conforms to RFC 8439 (Bernstein "ChaCha20 and Poly1305 for IETF
// Protocols").
//
// Status: luxcpp/crypto/aead/c-abi/c_aead.cpp returns CRYPTO_ERR_NOTIMPL for
// seal and open. Tests gated #[ignore] until the C-ABI body lands.

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

/// Length of the AEAD key in bytes (256 bits).
pub const KEY_LEN: usize = 32;
/// Length of the AEAD nonce in bytes (96 bits).
pub const NONCE_LEN: usize = 12;
/// Length of the Poly1305 authentication tag in bytes (128 bits).
pub const TAG_LEN: usize = 16;

/// Errors returned by the AEAD binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    /// Open() returned a tag-mismatch.
    Forged,
}

/// Encrypt `pt` under `(key, nonce, aad)`. `ct` must be sized exactly to
/// `pt.len()`. Writes the 16-byte tag into `tag`.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) -> Result<(), Error> {
    if ct.len() != pt.len() {
        return Err(Error::InternalError(-2));
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
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
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// Decrypt `ct` under `(key, nonce, aad, tag)`. `pt` must be sized exactly to
/// `ct.len()`.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    pt: &mut [u8],
) -> Result<(), Error> {
    if pt.len() != ct.len() {
        return Err(Error::InternalError(-2));
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
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
        -3 => Err(Error::Forged),
        other => Err(Error::InternalError(other)),
    }
}
