// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-blake2b: canonical Rust binding for Lux BLAKE2b C-ABI.
// RFC 7693 BLAKE2b-512 (default-length 64-byte digest, no key).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn blake2b(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of the default BLAKE2b digest in bytes (BLAKE2b-512).
pub const DIGEST_LEN: usize = 64;

/// Compute the BLAKE2b-512 digest of `input` (no key).
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake2b(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake2b returned non-zero status: {}", rc);
    out
}
