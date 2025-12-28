// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-poly-mul: canonical Rust binding for the Lux negacyclic
// polynomial-multiplication C-ABI. Multiplies polynomials in
// `Z_Q[X] / (X^n + 1)` via Schoolbook (n < 64) or NTT (n a power of two).
//
// Q is the Cyclone-FFT prime (998244353) with primitive root 3, fixed by the
// underlying C-ABI. Other (modulus, root) pairs return CRYPTO_ERR_INPUT.
//
// The ntt/poly_mul body is shipped (luxcpp/crypto/poly_mul/c-abi/c_poly_mul.cpp
// is a real implementation). This binding is byte-equal to the Go reference
// at github.com/luxfi/crypto/poly_mul.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn poly_mul(
        a: *const u64,
        b: *const u64,
        n: usize,
        modulus: u64,
        root: u64,
        out: *mut u64,
    ) -> c_int;
}

/// The Cyclone-FFT prime modulus (= 998244353). Fixed by the underlying C-ABI.
pub const CYCLONE_PRIME: u64 = 998244353;
/// Primitive root for the Cyclone-FFT prime.
pub const CYCLONE_PRIMITIVE_ROOT: u64 = 3;

/// Errors returned by the poly_mul binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
    InvalidLength,
}

/// Multiply two polynomials of length `n` over `Z_Q[X] / (X^n + 1)` for the
/// Cyclone-FFT prime. `out` must be sized to `n`. `modulus` and `root` must be
/// `CYCLONE_PRIME` and `CYCLONE_PRIMITIVE_ROOT` (other pairs are rejected by
/// the C-ABI).
#[inline]
pub fn multiply(
    a: &[u64],
    b: &[u64],
    modulus: u64,
    root: u64,
    out: &mut [u64],
) -> Result<(), Error> {
    if a.len() != b.len() || out.len() != a.len() {
        return Err(Error::InvalidLength);
    }
    // SAFETY: lengths checked above.
    let rc = unsafe {
        poly_mul(
            a.as_ptr(),
            b.as_ptr(),
            a.len(),
            modulus,
            root,
            out.as_mut_ptr(),
        )
    };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}
