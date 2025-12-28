// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-aead: canonical Rust binding for the Lux ChaCha20-Poly1305 AEAD
// C-ABI per RFC 8439. Links statically against `libaead.a` and
// `libaead_cpu.a` produced by `luxcpp/crypto/aead`.
//
// AEAD construction is "Authenticated Encryption with Associated Data"
// (Krovetz/Rogaway 2011). Key is 32 bytes, nonce is 12 bytes, tag is 16 bytes.
// Plaintext and ciphertext have the same length; tag is appended out-of-band
// in the C-ABI. The associated data ("aad") is authenticated but not
// encrypted.

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

/// Length of the ChaCha20-Poly1305 key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the ChaCha20-Poly1305 nonce in bytes (96-bit, RFC 8439).
pub const NONCE_LEN: usize = 12;
/// Length of the Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Errors returned by ChaCha20-Poly1305.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// One of the input buffers was malformed (e.g. NULL where a non-empty
    /// buffer was expected).
    BadInput,
    /// The Poly1305 tag did not match (decryption / verification failure).
    AuthFail,
    /// The C-ABI returned an unexpected status.
    Internal(c_int),
}

/// Encrypt-and-authenticate `pt` with associated data `aad`. Returns
/// `(ciphertext, tag)`. Ciphertext length matches plaintext length.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Error> {
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; TAG_LEN];
    // SAFETY: All pointers are valid for the call's duration; lengths are
    // expressed accurately to the C-ABI (NULL is allowed for empty slices).
    let rc = unsafe {
        aead_chacha20poly1305_seal(
            key.as_ptr(),
            nonce.as_ptr(),
            if aad.is_empty() { core::ptr::null() } else { aad.as_ptr() },
            aad.len(),
            if pt.is_empty() { core::ptr::null() } else { pt.as_ptr() },
            pt.len(),
            if ct.is_empty() { core::ptr::null_mut() } else { ct.as_mut_ptr() },
            tag.as_mut_ptr(),
        )
    };
    match rc {
        0 => Ok((ct, tag)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Verify-and-decrypt `ct` with `tag` and associated data `aad`. Returns
/// the plaintext. Length of plaintext equals length of ciphertext.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, Error> {
    let mut pt = vec![0u8; ct.len()];
    // SAFETY: All pointers are valid for the call's duration; lengths are
    // expressed accurately to the C-ABI (NULL is allowed for empty slices).
    let rc = unsafe {
        aead_chacha20poly1305_open(
            key.as_ptr(),
            nonce.as_ptr(),
            if aad.is_empty() { core::ptr::null() } else { aad.as_ptr() },
            aad.len(),
            if ct.is_empty() { core::ptr::null() } else { ct.as_ptr() },
            ct.len(),
            tag.as_ptr(),
            if pt.is_empty() { core::ptr::null_mut() } else { pt.as_mut_ptr() },
        )
    };
    match rc {
        0 => Ok(pt),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::AuthFail),
        x => Err(Error::Internal(x)),
    }
}
