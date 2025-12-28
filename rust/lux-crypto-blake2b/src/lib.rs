// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-blake2b: canonical Rust binding for the Lux BLAKE2b C-ABI.
//
// Links statically against `libblake2b.a` produced by `luxcpp/crypto/blake2b`,
// whose CPU body is the first-party BLAKE2b reference (Aumasson, Neves,
// Wilcox-O'Hearn, Winnerlein, "BLAKE2: simpler, smaller, fast as MD5", 2013).
// Conforms to RFC 7693.
//
// This binding exposes the unkeyed 64-byte digest (RFC 7693 §2.6 default).
//
// Reference test vector for "abc" is the RFC 7693 §F.4 test vector.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn blake2b(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a default BLAKE2b digest in bytes (RFC 7693).
pub const DIGEST_LEN: usize = 64;

/// Compute the unkeyed BLAKE2b-512 digest of `input`.
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake2b(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake2b returned non-zero status: {}", rc);
    out
}
