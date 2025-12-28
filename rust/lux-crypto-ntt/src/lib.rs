// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ntt: canonical Rust binding for Lux Number-Theoretic Transform.
// Operates in-place over a power-of-two coefficient vector under a chosen
// NTT-friendly prime modulus and primitive root of unity. Used directly by
// the FHE stack and by polynomial-commitment schemes.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ntt_forward(coeffs: *mut u64, n: usize, modulus: u64, root: u64) -> c_int;
    fn ntt_inverse(coeffs: *mut u64, n: usize, modulus: u64, root_inv: u64) -> c_int;
}

/// Errors returned by NTT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status.
    Internal(c_int),
    /// `n` was not a power of two.
    NotPowerOfTwo,
}

/// In-place forward NTT.
#[inline]
pub fn forward(coeffs: &mut [u64], modulus: u64, root: u64) -> Result<(), Error> {
    let n = coeffs.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(Error::NotPowerOfTwo);
    }
    // SAFETY: buffer length is power of two; pointer valid for the call.
    let rc = unsafe { ntt_forward(coeffs.as_mut_ptr(), n, modulus, root) };
    if rc == 0 { Ok(()) } else { Err(Error::Internal(rc)) }
}

/// In-place inverse NTT.
#[inline]
pub fn inverse(coeffs: &mut [u64], modulus: u64, root_inv: u64) -> Result<(), Error> {
    let n = coeffs.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(Error::NotPowerOfTwo);
    }
    // SAFETY: buffer length is power of two; pointer valid for the call.
    let rc = unsafe { ntt_inverse(coeffs.as_mut_ptr(), n, modulus, root_inv) };
    if rc == 0 { Ok(()) } else { Err(Error::Internal(rc)) }
}

/// Cyclone NTT prime modulus (Q = 119 * 2^23 + 1 = 998244353), matching
/// `luxcpp/crypto/ntt::Q`.
pub const CYCLONE_Q: u64 = 998_244_353;
/// Cyclone NTT primitive 2^MAX_LOG_N-th root of unity, matching
/// `luxcpp/crypto/ntt::PRIMITIVE_ROOT`.
pub const CYCLONE_ROOT: u64 = 629_671_588;
