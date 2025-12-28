// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-poly_mul: canonical Rust binding for the Lux polynomial-
// multiplication C-ABI over Z_Q[X]/(X^n + 1) where Q = 998244353.
//
// Negacyclic convolution (X^n = -1) — the lattice-crypto shape used by
// ML-KEM, ML-DSA, Ringtail. The C-ABI dispatcher chooses schoolbook
// (O(n^2), faster below n=64) or NTT (O(n log n)) automatically.
//
// Per-coefficient byte output is identical to the Go reference at
// github.com/luxfi/crypto/poly_mul (Mul / MulSchoolbook / MulNTT) — see
// KAT vectors in luxcpp/crypto/poly_mul/test/vectors/.
//
// Domain: STANDARD form on both sides. Inputs may be in [0, 2^64); reduced
// mod Q on entry. Outputs guaranteed in [0, Q).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
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

/// Cyclone-FFT prime: 998244353 = 119 * 2^23 + 1.
pub const Q: u64 = 998_244_353;

/// 2^16-th primitive root of unity mod Q. Pinned by the C-ABI: `multiply`
/// only accepts (Q, PRIMITIVE_ROOT).
pub const PRIMITIVE_ROOT: u64 = 629_671_588;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyMulError {
    /// Length mismatch, non-cyclone (modulus, root), or n=0.
    Input,
}

/// Compute c = a * b in Z_Q[X]/(X^n + 1) where n = a.len() = b.len().
///
/// Picks schoolbook below n=64 and the negacyclic NTT path otherwise.
/// Returns a freshly allocated `Vec<u64>` of length n.
#[inline]
pub fn multiply(a: &[u64], b: &[u64]) -> Result<Vec<u64>, PolyMulError> {
    if a.is_empty() || a.len() != b.len() {
        return Err(PolyMulError::Input);
    }
    let n = a.len();
    let mut out = vec![0u64; n];
    // SAFETY: pointers valid for the call's duration; out is sized to n.
    let rc = unsafe {
        poly_mul(
            a.as_ptr(),
            b.as_ptr(),
            n,
            Q,
            PRIMITIVE_ROOT,
            out.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Ok(out)
    } else {
        Err(PolyMulError::Input)
    }
}

/// Compute c = a * b into a caller-provided buffer. Returns Err if shapes
/// are wrong or the C-ABI returns non-zero.
#[inline]
pub fn multiply_into(a: &[u64], b: &[u64], out: &mut [u64]) -> Result<(), PolyMulError> {
    if a.is_empty() || a.len() != b.len() || out.len() != a.len() {
        return Err(PolyMulError::Input);
    }
    let n = a.len();
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe {
        poly_mul(
            a.as_ptr(),
            b.as_ptr(),
            n,
            Q,
            PRIMITIVE_ROOT,
            out.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(PolyMulError::Input)
    }
}
