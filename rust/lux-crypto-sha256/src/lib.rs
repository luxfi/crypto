// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-sha256: canonical Rust binding for the Lux SHA-256 C-ABI.
//
// Links statically against `libsha256.a` and `libsha256_cpu.a` produced by
// `luxcpp/crypto/sha256`. The C-ABI is FIPS 180-4 SHA-256 over an arbitrary
// byte input, producing a 32-byte digest. Body is a portable C++ implementation
// with optional ARMv8 SHA2 / x86 SHA-NI dispatch.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn sha256(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Compute the SHA-256 digest of `input`.
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: input pointer is valid for `input.len()` bytes; output sized to digest.
    let rc = unsafe { sha256(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "sha256 returned non-zero status: {}", rc);
    out
}

/// Compute the SHA-256 digest of `input` into a caller-supplied buffer.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; DIGEST_LEN]) -> &'a [u8; DIGEST_LEN] {
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { sha256(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "sha256 returned non-zero status: {}", rc);
    output
}
