// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-ntt: canonical Rust binding for the Lux NTT (Number Theoretic
// Transform) C-ABI. Used by FHE primitives and exposed here as a building
// block.
//
// Status: luxcpp/crypto/ntt/c-abi/c_ntt.cpp returns CRYPTO_ERR_NOTIMPL for
// forward / inverse / poly_mul. Tests gated #[ignore] until the C-ABI body
// lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn ntt_forward(coeffs: *mut u64, n: usize, modulus: u64, root: u64) -> c_int;
    fn ntt_inverse(coeffs: *mut u64, n: usize, modulus: u64, root_inv: u64) -> c_int;
    fn poly_mul(
        a: *const u64,
        b: *const u64,
        n: usize,
        modulus: u64,
        root: u64,
        out: *mut u64,
    ) -> c_int;
}

/// Cyclone NTT prime: 998244353 = 119·2²³ + 1, a 30-bit NTT-friendly prime
/// used by the Lux Cyclone polynomial backend (see luxcpp/crypto/ntt).
pub const CYCLONE_Q: u64 = 998_244_353;
/// Generator of the multiplicative group (Z/CYCLONE_Q)* used to derive
/// primitive roots of unity for any power-of-two transform size.
pub const CYCLONE_G: u64 = 3;
/// Primitive 16th root of unity (primitive 2n-th root for n = 8) over
/// `Z_{CYCLONE_Q}`. Equals `CYCLONE_G^((CYCLONE_Q-1)/16) mod CYCLONE_Q`,
/// satisfying `CYCLONE_ROOT^16 ≡ 1` and `CYCLONE_ROOT^8 ≡ −1 (mod CYCLONE_Q)`.
/// Suitable for the n=8 KAT in `tests/kat.rs`; for other n the root must be
/// derived from `CYCLONE_G` at runtime.
pub const CYCLONE_ROOT: u64 = 929_031_873;

/// Errors returned by the NTT binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InternalError(c_int),
}

/// In-place forward NTT over `coeffs[0..n]` mod `modulus` with primitive
/// 2n-th root of unity `root`. `n` must be a power of two.
#[inline]
pub fn forward(coeffs: &mut [u64], modulus: u64, root: u64) -> Result<(), Error> {
    // SAFETY: caller asserts `coeffs` is power-of-two length.
    let rc = unsafe { ntt_forward(coeffs.as_mut_ptr(), coeffs.len(), modulus, root) };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// In-place inverse NTT over `coeffs[0..n]` mod `modulus` with the inverse of
/// the primitive 2n-th root of unity `root_inv`.
#[inline]
pub fn inverse(coeffs: &mut [u64], modulus: u64, root_inv: u64) -> Result<(), Error> {
    // SAFETY: caller asserts `coeffs` is power-of-two length.
    let rc = unsafe { ntt_inverse(coeffs.as_mut_ptr(), coeffs.len(), modulus, root_inv) };
    match rc { 0 => Ok(()), other => Err(Error::InternalError(other)) }
}

/// Polynomial multiplication over `Z_modulus[X]/(X^n - 1)` via NTT. `out`
/// must be sized to `n` and `a`/`b` must each be sized to `n`.
#[inline]
pub fn poly_multiply(
    a: &[u64],
    b: &[u64],
    modulus: u64,
    root: u64,
    out: &mut [u64],
) -> Result<(), Error> {
    if a.len() != b.len() || out.len() != a.len() {
        return Err(Error::InternalError(-2));
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
