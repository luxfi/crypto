// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-blake3: canonical Rust binding for the Lux BLAKE3 C-ABI.
//
// Links statically against `libblake3.a` and `libblake3_cpu.a` produced by
// `luxcpp/crypto/blake3`. The C-ABI surface currently exposes the default
// 32-byte hash mode only; keyed_hash, derive_key and the XOF will land
// alongside the first-class CPU body and be exposed here at that time.
//
// Byte-equal to upstream b3sum / blake3-py for the default `hash` mode.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn blake3(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a default BLAKE3 digest in bytes.
pub const OUT_LEN: usize = 32;

/// Compute the default 32-byte BLAKE3 digest of `input`.
#[inline]
pub fn hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut out = [0u8; OUT_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake3(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake3 returned non-zero status: {}", rc);
    out
}

/// Compute the default 32-byte BLAKE3 digest of `input` into a caller-supplied
/// buffer. Returns the same buffer for ergonomic chaining.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; OUT_LEN]) -> &'a [u8; OUT_LEN] {
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake3(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake3 returned non-zero status: {}", rc);
    output
}
