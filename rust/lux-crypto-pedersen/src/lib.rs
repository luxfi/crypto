// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-pedersen: canonical Rust binding for Lux Pedersen commitment
// C-ABI. Pedersen, "Non-interactive and information-theoretic secure
// verifiable secret sharing" (1991), classical perfectly-hiding commitment.
//
// Status: luxcpp/crypto/pedersen/c-abi/c_pedersen.cpp returns CRYPTO_ERR_NOTIMPL.
// Tests gated #[ignore] until the C-ABI body lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn pedersen_commit(values: *const u8, n: usize, blinding: *const u8, commit: *mut u8) -> c_int;
    fn pedersen_verify(commit: *const u8, values: *const u8, n: usize, blinding: *const u8) -> c_int;
}

/// Length of a Pedersen commitment (33 bytes, compressed secp256k1 point).
pub const COMMIT_LEN: usize = 33;
/// Length of a 32-byte blinding factor.
pub const BLINDING_LEN: usize = 32;

/// Errors returned by the Pedersen binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidCommitment,
}

/// Compute Pedersen commitment over `n` 32-byte values with the given blinding factor.
#[inline]
pub fn commit(
    values: &[u8],
    n: usize,
    blinding: &[u8; BLINDING_LEN],
) -> Result<[u8; COMMIT_LEN], Error> {
    let mut out = [0u8; COMMIT_LEN];
    // SAFETY: caller asserts values.len() >= n * 32.
    let rc = unsafe {
        pedersen_commit(values.as_ptr(), n, blinding.as_ptr(), out.as_mut_ptr())
    };
    match rc { 0 => Ok(out), other => Err(Error::InternalError(other)) }
}

/// Verify that `commit` was produced from `values` and `blinding`.
#[inline]
pub fn verify(
    commit: &[u8; COMMIT_LEN],
    values: &[u8],
    n: usize,
    blinding: &[u8; BLINDING_LEN],
) -> Result<(), Error> {
    // SAFETY: caller asserts values.len() >= n * 32.
    let rc = unsafe {
        pedersen_verify(commit.as_ptr(), values.as_ptr(), n, blinding.as_ptr())
    };
    match rc {
        0 | 1 => Ok(()),
        -3 => Err(Error::InvalidCommitment),
        other => Err(Error::InternalError(other)),
    }
}
