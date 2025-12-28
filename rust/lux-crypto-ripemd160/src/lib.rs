// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ripemd160: canonical Rust binding for the Lux RIPEMD-160 C-ABI.
//
// Links statically against `libripemd160.a` produced by `luxcpp/crypto/ripemd160`,
// whose CPU body is the first-party RIPEMD-160 reference (Dobbertin, Bosselaers,
// Preneel, "RIPEMD-160: A Strengthened Version of RIPEMD", 1996).
//
// Used by Bitcoin/Ethereum addresses (`RIPEMD160(SHA256(pk))`) and the EVM
// `RIPEMD160` precompile at address 0x03.
//
// Reference test vector for the empty input is `9c1185a5c5e9fc54612808977ee8f548b2258d31`.

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
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { ripemd160(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "ripemd160 returned non-zero status: {}", rc);
    out
}
