// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-blake2b: canonical Rust binding for the Lux BLAKE2b C-ABI.
//
// Links statically against `libblake2b.a` and `libblake2b_cpu.a` produced
// by `luxcpp/crypto/blake2b`. BLAKE2b per RFC 7693 with the default 64-byte
// (512-bit) digest length and unkeyed mode. The C-ABI signature matches the
// EIP-152 BLAKE2b precompile semantics for the unkeyed full-state hash.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn blake2b(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a BLAKE2b digest in bytes (512-bit default).
pub const DIGEST_LEN: usize = 64;

/// Compute the unkeyed BLAKE2b digest of `input` (64-byte output).
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake2b(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake2b returned non-zero status: {}", rc);
    out
}

/// Compute the BLAKE2b digest of `input` into a caller-supplied buffer.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; DIGEST_LEN]) -> &'a [u8; DIGEST_LEN] {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { blake2b(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake2b returned non-zero status: {}", rc);
    output
}
