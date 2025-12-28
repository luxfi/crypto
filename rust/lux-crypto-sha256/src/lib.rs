// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-sha256: canonical Rust binding for the Lux SHA-256 C-ABI.
//
// Links statically against `libsha256.a` produced by `luxcpp/crypto/sha256`,
// whose CPU body is the first-party SHA-256 reference. Conforms to FIPS 180-4
// §6.2 ("Secure Hash Algorithm SHA-256").
//
// Reference test vector for the empty input is
// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn sha256(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Errors returned by the SHA-256 binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
}

/// Compute the SHA-256 digest of `input`.
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { sha256(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "sha256 returned non-zero status: {}", rc);
    out
}

/// Compute the SHA-256 digest of `input` into a caller-supplied buffer.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; DIGEST_LEN]) -> &'a [u8; DIGEST_LEN] {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { sha256(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "sha256 returned non-zero status: {}", rc);
    output
}
