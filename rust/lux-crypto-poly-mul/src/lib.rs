// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-poly-mul: canonical Rust binding for Lux polynomial multiplication
// in the negacyclic ring R_q = Z_q[x] / (x^n + 1). Currently restricted to the
// Cyclone NTT prime; see lux-crypto-ntt for the generic transform path.

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

/// Errors returned by `multiply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// C-ABI returned an error status (e.g. unsupported (modulus, root)).
    Internal(c_int),
    /// Input lengths disagreed.
    LengthMismatch,
}

/// Cyclone NTT prime modulus (Q = 119 * 2^23 + 1 = 998244353), matching
/// `luxcpp/crypto/ntt::Q`.
pub const CYCLONE_Q: u64 = 998_244_353;
/// Cyclone NTT primitive 2^MAX_LOG_N-th root of unity, matching
/// `luxcpp/crypto/ntt::PRIMITIVE_ROOT`.
pub const CYCLONE_ROOT: u64 = 629_671_588;

/// Multiply two polynomials in R_q = Z_q[x] / (x^n + 1).
///
/// `a`, `b`, and `out` must all have the same length `n`, which must be a
/// power of two.
#[inline]
pub fn multiply(
    a: &[u64],
    b: &[u64],
    out: &mut [u64],
    modulus: u64,
    root: u64,
) -> Result<(), Error> {
    if a.len() != b.len() || a.len() != out.len() {
        return Err(Error::LengthMismatch);
    }
    // SAFETY: pointers valid for the call's duration; lengths checked above.
    let rc = unsafe {
        poly_mul(a.as_ptr(), b.as_ptr(), a.len(), modulus, root, out.as_mut_ptr())
    };
    if rc == 0 { Ok(()) } else { Err(Error::Internal(rc)) }
}
