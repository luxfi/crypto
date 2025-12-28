// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ripemd160: canonical Rust binding for the Lux RIPEMD-160 C-ABI.
//
// Links statically against `libripemd160.a` and `libripemd160_cpu.a` produced
// by `luxcpp/crypto/ripemd160`. RIPEMD-160 per "RIPEMD-160: A Strengthened
// Version of RIPEMD" (Dobbertin, Bosselaers, Preneel, 1996). Output digest
// is 20 bytes. Used by Bitcoin (P2PKH) and the EVM `RIPEMD160` precompile
// at address 0x03.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ripemd160(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a RIPEMD-160 digest in bytes.
pub const DIGEST_LEN: usize = 20;

/// Compute the RIPEMD-160 digest of `input`.
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: pointers are valid for the call's duration; output is sized
    // to the C-ABI's documented `DIGEST_LEN` write width.
    let rc = unsafe { ripemd160(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "ripemd160 returned non-zero status: {}", rc);
    out
}

/// Compute the RIPEMD-160 digest of `input` into a caller-supplied buffer.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; DIGEST_LEN]) -> &'a [u8; DIGEST_LEN] {
    // SAFETY: pointers are valid for the call's duration.
    let rc = unsafe { ripemd160(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "ripemd160 returned non-zero status: {}", rc);
    output
}
