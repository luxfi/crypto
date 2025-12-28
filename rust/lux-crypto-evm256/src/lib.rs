// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-evm256: canonical Rust binding for the Lux EVM 256-bit math
// primitives `addmod` (a + b) mod m and `mulmod` (a * b) mod m. Inputs are
// canonical big-endian 256-bit unsigned integers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn evm256_mulmod(a: *const u8, b: *const u8, m: *const u8, out: *mut u8) -> c_int;
    fn evm256_addmod(a: *const u8, b: *const u8, m: *const u8, out: *mut u8) -> c_int;
}

/// Length of a 256-bit operand in bytes.
pub const WORD_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    Internal(c_int),
}

/// Compute `(a * b) mod m` over canonical 256-bit big-endian operands.
/// EVM convention: when m == 0, the result is 0.
pub fn mulmod(
    a: &[u8; WORD_LEN],
    b: &[u8; WORD_LEN],
    m: &[u8; WORD_LEN],
) -> Result<[u8; WORD_LEN], Error> {
    let mut out = [0u8; WORD_LEN];
    // SAFETY: All buffers are 32 bytes.
    let rc = unsafe { evm256_mulmod(a.as_ptr(), b.as_ptr(), m.as_ptr(), out.as_mut_ptr()) };
    match rc {
        0 => Ok(out),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Compute `(a + b) mod m` over canonical 256-bit big-endian operands.
/// EVM convention: when m == 0, the result is 0.
pub fn addmod(
    a: &[u8; WORD_LEN],
    b: &[u8; WORD_LEN],
    m: &[u8; WORD_LEN],
) -> Result<[u8; WORD_LEN], Error> {
    let mut out = [0u8; WORD_LEN];
    // SAFETY: All buffers are 32 bytes.
    let rc = unsafe { evm256_addmod(a.as_ptr(), b.as_ptr(), m.as_ptr(), out.as_mut_ptr()) };
    match rc {
        0 => Ok(out),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}
