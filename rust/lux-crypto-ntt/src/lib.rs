// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ntt: canonical Rust binding for the Lux NTT C-ABI.
//
// Links statically against `libntt_cpu.a` produced by `luxcpp/crypto/ntt`.
// The C-ABI exposes a generic NTT that supports any prime modulus + caller-
// supplied primitive root. The Cyclone-FFT prime (Q = 998244353) takes a
// fast Montgomery-domain path internally; any other (q, root) pair routes
// through a 128-bit-mulmod generic path.
//
// Per-coefficient byte output is identical to the Go reference at
// github.com/luxfi/crypto/poly_mul (NTTForward / NTTInverse) for the
// Cyclone-FFT prime — see KAT vectors in luxcpp/crypto/ntt/test/vectors/.
//
// Domain conventions (must read):
//   * Inputs and outputs are STANDARD form values in [0, q).
//   * Inputs may be in [0, 2^64); reduced mod q on entry.
//   * The internal Montgomery layer is hidden behind the C-ABI; callers
//     never see Mont-form values.
//   * INTT performs the 1/n scaling internally; you do not need to.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ntt_forward(coeffs: *mut u64, n: usize, modulus: u64, root: u64) -> c_int;
    fn ntt_inverse(coeffs: *mut u64, n: usize, modulus: u64, root_inv: u64) -> c_int;
}

/// Cyclone-FFT prime: 998244353 = 119 * 2^23 + 1.
pub const Q: u64 = 998_244_353;

/// 2^16-th primitive root of unity mod Q. The fast path is engaged when
/// `(modulus, root) == (Q, PRIMITIVE_ROOT)`.
pub const PRIMITIVE_ROOT: u64 = 629_671_588;

/// Errors returned by the NTT C-ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NttError {
    /// Malformed input (n not power of two, n=0, n exceeds 2^16, modulus=0,
    /// or pointer null).
    Input,
}

/// Forward NTT in place. `data.len()` must be a power of two, `data.len() >= 1`,
/// `data.len() <= 2^16`. Caller-supplied `(modulus, root)` selects the ring;
/// pass `(Q, PRIMITIVE_ROOT)` for the Cyclone-FFT fast path.
#[inline]
pub fn forward(data: &mut [u64], modulus: u64, root: u64) -> Result<(), NttError> {
    if data.is_empty() {
        return Err(NttError::Input);
    }
    // SAFETY: pointer is valid for `data.len()` writes for the call's duration.
    let rc = unsafe { ntt_forward(data.as_mut_ptr(), data.len(), modulus, root) };
    if rc == 0 { Ok(()) } else { Err(NttError::Input) }
}

/// Inverse NTT in place (includes the 1/n scaling). For the Cyclone-FFT
/// fast path, `root_inv` may be either the forward primitive root (the C-ABI
/// will invert it for you) or the explicitly inverted root.
#[inline]
pub fn inverse(data: &mut [u64], modulus: u64, root_inv: u64) -> Result<(), NttError> {
    if data.is_empty() {
        return Err(NttError::Input);
    }
    // SAFETY: pointer is valid for `data.len()` writes for the call's duration.
    let rc = unsafe { ntt_inverse(data.as_mut_ptr(), data.len(), modulus, root_inv) };
    if rc == 0 { Ok(()) } else { Err(NttError::Input) }
}
