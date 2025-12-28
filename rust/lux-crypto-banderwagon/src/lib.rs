// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-banderwagon: canonical Rust binding for the Lux Banderwagon
// C-ABI. Banderwagon is the prime-order subgroup of Bandersnatch (twisted
// Edwards over BLS12-381 Fr); the underlying group for Verkle / IPA /
// Pedersen vector commitments in the EIP-7805 stateless-Ethereum suite.
//
// Encoding:
//   * 32-byte compressed form  (canonical big-endian X with Y-sign folded in)
//   * 64-byte uncompressed (X || Y, big-endian Fp).

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn banderwagon_encode(point_in: *const u8, out: *mut u8) -> c_int;
    fn banderwagon_decode(input: *const u8, point_out: *mut u8) -> c_int;
    fn banderwagon_add(a: *const u8, b: *const u8, out: *mut u8) -> c_int;
    fn banderwagon_double(a: *const u8, out: *mut u8) -> c_int;
    fn banderwagon_neg(a: *const u8, out: *mut u8) -> c_int;
    fn banderwagon_scalar_mul(scalar: *const u8, point: *const u8, out: *mut u8) -> c_int;
    fn banderwagon_msm(
        points: *const u8,
        scalars: *const u8,
        n: usize,
        out: *mut u8,
    ) -> c_int;
    fn banderwagon_msm_compressed(
        points_compressed: *const u8,
        scalars: *const u8,
        n: usize,
        out_compressed: *mut u8,
    ) -> c_int;
    fn banderwagon_generator(out: *mut u8);
    fn banderwagon_identity(out: *mut u8);
    fn banderwagon_equal(a: *const u8, b: *const u8) -> c_int;
}

/// Length of a compressed Banderwagon point in bytes.
pub const COMPRESSED_LEN: usize = 32;
/// Length of an uncompressed Banderwagon point in bytes (X || Y).
pub const UNCOMPRESSED_LEN: usize = 64;
/// Length of a Banderwagon scalar (Fr element) in bytes.
pub const SCALAR_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Malformed point input (e.g. non-canonical Fp).
    BadInput,
    /// The 32-byte compressed input failed the subgroup decode check.
    SubgroupFail,
    /// Internal C-ABI error.
    Internal(c_int),
}

fn map_rc(rc: c_int) -> Result<(), Error> {
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::SubgroupFail),
        x => Err(Error::Internal(x)),
    }
}

/// Encode a 64-byte uncompressed point to its 32-byte compressed form.
pub fn encode(point: &[u8; UNCOMPRESSED_LEN]) -> Result<[u8; COMPRESSED_LEN], Error> {
    let mut out = [0u8; COMPRESSED_LEN];
    // SAFETY: All pointers valid; lengths from typed array sizes.
    let rc = unsafe { banderwagon_encode(point.as_ptr(), out.as_mut_ptr()) };
    map_rc(rc).map(|_| out)
}

/// Decode a 32-byte compressed point to its 64-byte uncompressed form.
pub fn decode(input: &[u8; COMPRESSED_LEN]) -> Result<[u8; UNCOMPRESSED_LEN], Error> {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: All pointers valid.
    let rc = unsafe { banderwagon_decode(input.as_ptr(), out.as_mut_ptr()) };
    map_rc(rc).map(|_| out)
}

/// Group addition.
pub fn add(
    a: &[u8; UNCOMPRESSED_LEN],
    b: &[u8; UNCOMPRESSED_LEN],
) -> Result<[u8; UNCOMPRESSED_LEN], Error> {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: All pointers valid.
    let rc = unsafe { banderwagon_add(a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
    map_rc(rc).map(|_| out)
}

/// Group doubling.
pub fn double(a: &[u8; UNCOMPRESSED_LEN]) -> Result<[u8; UNCOMPRESSED_LEN], Error> {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: All pointers valid.
    let rc = unsafe { banderwagon_double(a.as_ptr(), out.as_mut_ptr()) };
    map_rc(rc).map(|_| out)
}

/// Group negation.
pub fn neg(a: &[u8; UNCOMPRESSED_LEN]) -> Result<[u8; UNCOMPRESSED_LEN], Error> {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: All pointers valid.
    let rc = unsafe { banderwagon_neg(a.as_ptr(), out.as_mut_ptr()) };
    map_rc(rc).map(|_| out)
}

/// Scalar multiplication.
pub fn scalar_mul(
    scalar: &[u8; SCALAR_LEN],
    point: &[u8; UNCOMPRESSED_LEN],
) -> Result<[u8; UNCOMPRESSED_LEN], Error> {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: All pointers valid.
    let rc = unsafe { banderwagon_scalar_mul(scalar.as_ptr(), point.as_ptr(), out.as_mut_ptr()) };
    map_rc(rc).map(|_| out)
}

/// Multi-scalar multiplication.
pub fn msm(points: &[u8], scalars: &[u8]) -> Result<[u8; UNCOMPRESSED_LEN], Error> {
    if points.len() % UNCOMPRESSED_LEN != 0 || scalars.len() % SCALAR_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n_points = points.len() / UNCOMPRESSED_LEN;
    let n_scalars = scalars.len() / SCALAR_LEN;
    if n_points != n_scalars {
        return Err(Error::BadInput);
    }
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: lengths checked above; n derived from the smaller of equal counts.
    let rc = unsafe {
        banderwagon_msm(points.as_ptr(), scalars.as_ptr(), n_points, out.as_mut_ptr())
    };
    map_rc(rc).map(|_| out)
}

/// Multi-scalar multiplication over compressed-input/compressed-output.
pub fn msm_compressed(points: &[u8], scalars: &[u8]) -> Result<[u8; COMPRESSED_LEN], Error> {
    if points.len() % COMPRESSED_LEN != 0 || scalars.len() % SCALAR_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n_points = points.len() / COMPRESSED_LEN;
    let n_scalars = scalars.len() / SCALAR_LEN;
    if n_points != n_scalars {
        return Err(Error::BadInput);
    }
    let mut out = [0u8; COMPRESSED_LEN];
    // SAFETY: lengths checked above.
    let rc = unsafe {
        banderwagon_msm_compressed(
            points.as_ptr(),
            scalars.as_ptr(),
            n_points,
            out.as_mut_ptr(),
        )
    };
    map_rc(rc).map(|_| out)
}

/// Banderwagon group generator (canonical 64-byte X || Y).
pub fn generator() -> [u8; UNCOMPRESSED_LEN] {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: 64-byte sized buffer matches C-ABI.
    unsafe { banderwagon_generator(out.as_mut_ptr()) };
    out
}

/// Banderwagon identity (point at infinity in the prime-order subgroup).
pub fn identity() -> [u8; UNCOMPRESSED_LEN] {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    // SAFETY: 64-byte sized buffer matches C-ABI.
    unsafe { banderwagon_identity(out.as_mut_ptr()) };
    out
}

/// Banderwagon equality (subgroup-pair semantics).
pub fn equal(a: &[u8; UNCOMPRESSED_LEN], b: &[u8; UNCOMPRESSED_LEN]) -> Result<bool, Error> {
    // SAFETY: 64-byte buffers.
    let rc = unsafe { banderwagon_equal(a.as_ptr(), b.as_ptr()) };
    match rc {
        1 => Ok(true),
        0 => Ok(false),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}
