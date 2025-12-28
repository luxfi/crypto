// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-bn254: canonical Rust binding for the Lux BN254 (alt_bn128)
// pairing C-ABI. Wired to the EVM precompiles at addresses 0x06 (add), 0x07
// (mul), and 0x08 (pairing).
//
// Status: luxcpp/crypto/bn254/c-abi/c_bn254.cpp returns CRYPTO_ERR_NOTIMPL
// for add/mul/pairing. Tests gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn bn254_add(input: *const u8, output: *mut u8) -> c_int;
    fn bn254_mul(input: *const u8, output: *mut u8) -> c_int;
    fn bn254_pairing(pairs: *const u8, n_pairs: usize, output: *mut u8) -> c_int;
}

/// Errors returned by the BN254 binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
}

/// EVM ALT_BN128_ADD precompile (0x06): adds two G1 points (each 64 bytes,
/// X || Y, big-endian). Input = 128 bytes, output = 64 bytes.
#[inline]
pub fn add(input: &[u8; 128]) -> Result<[u8; 64], Error> {
    let mut out = [0u8; 64];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { bn254_add(input.as_ptr(), out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// EVM ALT_BN128_MUL precompile (0x07): scalar-multiplies a G1 point. Input =
/// 96 bytes (P[64] || s[32]), output = 64 bytes (Q = s*P).
#[inline]
pub fn mul(input: &[u8; 96]) -> Result<[u8; 64], Error> {
    let mut out = [0u8; 64];
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe { bn254_mul(input.as_ptr(), out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// EVM ALT_BN128_PAIRING precompile (0x08): n pairs of (G1[64] || G2[128]),
/// output = 32-byte scalar (1 if product == identity, else 0).
#[inline]
pub fn pairing(pairs: &[u8], n_pairs: usize) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    // SAFETY: caller asserts pairs.len() >= n_pairs * 192.
    let rc = unsafe { bn254_pairing(pairs.as_ptr(), n_pairs, out.as_mut_ptr()) };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}
