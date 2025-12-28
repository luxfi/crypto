// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-evm256: canonical Rust binding for Lux 256-bit modular arithmetic.
// Mirrors EVM `MULMOD` and `ADDMOD` semantics over big-endian uint256 inputs.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn evm256_mulmod(a: *const u8, b: *const u8, m: *const u8, out: *mut u8) -> c_int;
    fn evm256_addmod(a: *const u8, b: *const u8, m: *const u8, out: *mut u8) -> c_int;
}

/// Length of an EVM uint256 in bytes (big-endian).
pub const WORD_LEN: usize = 32;

/// Compute `(a * b) mod m` over big-endian uint256 inputs.
///
/// EVM semantics: when `m == 0` the result is `0` (rather than panicking).
#[inline]
pub fn mulmod(
    a: &[u8; WORD_LEN],
    b: &[u8; WORD_LEN],
    m: &[u8; WORD_LEN],
    out: &mut [u8; WORD_LEN],
) -> Result<(), c_int> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { evm256_mulmod(a.as_ptr(), b.as_ptr(), m.as_ptr(), out.as_mut_ptr()) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Compute `(a + b) mod m` over big-endian uint256 inputs.
///
/// EVM semantics: when `m == 0` the result is `0`.
#[inline]
pub fn addmod(
    a: &[u8; WORD_LEN],
    b: &[u8; WORD_LEN],
    m: &[u8; WORD_LEN],
    out: &mut [u8; WORD_LEN],
) -> Result<(), c_int> {
    // SAFETY: pointers valid for the call's duration; buffers sized exactly.
    let rc = unsafe { evm256_addmod(a.as_ptr(), b.as_ptr(), m.as_ptr(), out.as_mut_ptr()) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}
