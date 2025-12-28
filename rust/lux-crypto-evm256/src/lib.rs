// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-evm256: canonical Rust binding for the Lux EVM 256-bit big-int
// math primitives. Wired to the EVM precompile at address 0x05 (modexp,
// EIP-198) and the EVM `MULMOD` / `ADDMOD` opcodes.
//
// Status: luxcpp/crypto/modexp/c-abi/c_modexp.cpp returns CRYPTO_ERR_NOTIMPL
// for modexp/evm256_mulmod/evm256_addmod. Tests gated #[ignore] until the
// C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn modexp(
        base: *const u8,
        base_len: usize,
        exp: *const u8,
        exp_len: usize,
        modulus: *const u8,
        mod_len: usize,
        out: *mut u8,
    ) -> c_int;
    fn evm256_mulmod(a: *const u8, b: *const u8, m: *const u8, out: *mut u8) -> c_int;
    fn evm256_addmod(a: *const u8, b: *const u8, m: *const u8, out: *mut u8) -> c_int;
}

/// Errors returned by the EVM-256 binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidLength,
}

/// EIP-198 modular exponentiation: out = base^exp mod modulus.
/// `out` must be sized exactly to `mod_len` bytes.
#[inline]
pub fn mod_exp(base: &[u8], exp: &[u8], modulus: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.len() != modulus.len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: pointers valid for the call's duration; out length checked.
    let rc = unsafe {
        modexp(
            base.as_ptr(),
            base.len(),
            exp.as_ptr(),
            exp.len(),
            modulus.as_ptr(),
            modulus.len(),
            out.as_mut_ptr(),
        )
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// EVM `MULMOD` opcode: out = (a * b) mod m, all 256-bit big-endian.
#[inline]
pub fn mulmod(a: &[u8; 32], b: &[u8; 32], m: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { evm256_mulmod(a.as_ptr(), b.as_ptr(), m.as_ptr(), out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// EVM `ADDMOD` opcode: out = (a + b) mod m, all 256-bit big-endian.
#[inline]
pub fn addmod(a: &[u8; 32], b: &[u8; 32], m: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { evm256_addmod(a.as_ptr(), b.as_ptr(), m.as_ptr(), out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}
