// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-pedersen: canonical Rust binding for the Lux Banderwagon
// Pedersen vector-commitment C-ABI.
//
//   commit = sum_{i=0..n-1} G_i * values[i] + H * blinding   (32-byte
//                                                              compressed)
//
// G_i is the i-th vendored Verkle DeterministicGenerator (seed
// "eth_verkle_oct_2021"); H is the (256)-th generator from the same
// construction (one past the 256-element Verkle SRS).

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn pedersen_commit(
        values: *const u8,
        n: usize,
        blinding: *const u8,
        commit: *mut u8,
    ) -> c_int;

    fn pedersen_verify(
        commit: *const u8,
        values: *const u8,
        n: usize,
        blinding: *const u8,
    ) -> c_int;
}

/// Length of the Banderwagon-compressed commitment.
pub const COMMIT_LEN: usize = 32;
/// Length of a single value (Fr scalar) in bytes.
pub const VALUE_LEN: usize = 32;
/// Length of the blinding (Fr scalar) in bytes.
pub const BLINDING_LEN: usize = 32;
/// Maximum number of values supported (matches the 256-element SRS).
pub const MAX_VALUES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadInput,
    LengthExceeded,
    VerifyFail,
    Internal(c_int),
}

/// Compute a Pedersen commitment over `values` (each 32 bytes) with the
/// given blinding (32 bytes). Returns the canonical 32-byte compressed
/// commitment.
pub fn commit(values: &[u8], blinding: &[u8; BLINDING_LEN]) -> Result<[u8; COMMIT_LEN], Error> {
    if values.len() % VALUE_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = values.len() / VALUE_LEN;
    if n > MAX_VALUES {
        return Err(Error::LengthExceeded);
    }
    let mut out = [0u8; COMMIT_LEN];
    // SAFETY: lengths checked; pointers valid.
    let rc = unsafe {
        pedersen_commit(values.as_ptr(), n, blinding.as_ptr(), out.as_mut_ptr())
    };
    match rc {
        0 => Ok(out),
        -1 => Err(Error::BadInput),
        -2 => Err(Error::LengthExceeded),
        x => Err(Error::Internal(x)),
    }
}

/// Verify a Pedersen commitment.
pub fn verify(
    commit: &[u8; COMMIT_LEN],
    values: &[u8],
    blinding: &[u8; BLINDING_LEN],
) -> Result<(), Error> {
    if values.len() % VALUE_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = values.len() / VALUE_LEN;
    // SAFETY: lengths checked.
    let rc = unsafe {
        pedersen_verify(commit.as_ptr(), values.as_ptr(), n, blinding.as_ptr())
    };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}
