// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-secp256k1: canonical Rust binding for the Lux secp256k1 C-ABI.
//
// Links statically against `libsecp256k1_cpu.a` produced by
// `luxcpp/crypto/secp256k1`. The currently exposed C-ABI is the
// Ethereum-style ECDSA public-key recovery primitive used by the
// `ecrecover` precompile (address `0x0000...01`).
//
// Reference: SEC1 v2 (Standards for Efficient Cryptography Group, "SEC 1:
// Elliptic Curve Cryptography", 2009-05-21), section 4.1.6 ("Public Key
// Recovery Operation"); EVM Yellow Paper Appendix E (`ECREC` precompile).
//
// All multi-byte buffers are big-endian. The secp256k1 group order n and
// half-order n/2 are encoded into Ethereum's signature malleability rules
// (EIP-2: `s` must be in the lower half).

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

/// Status codes returned by the secp256k1 C-ABI.
///
/// Mirrors `luxcpp/crypto/secp256k1/c-abi/c_secp256k1.cpp`. Each variant has
/// the same numeric value as the corresponding C return code.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    InvalidR = 1,
    InvalidS = 2,
    InvalidV = 3,
    NoSqrt = 4,
    AtInfinity = 5,
    NullArg = 6,
    BufferLen = 7,
}

impl Status {
    /// Convert a raw `c_int` from a libcrypto secp256k1 call to the typed enum.
    /// Returns `None` for unknown values; callers should treat that as a bug.
    pub fn from_int(v: c_int) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidR),
            2 => Some(Self::InvalidS),
            3 => Some(Self::InvalidV),
            4 => Some(Self::NoSqrt),
            5 => Some(Self::AtInfinity),
            6 => Some(Self::NullArg),
            7 => Some(Self::BufferLen),
            _ => None,
        }
    }
}

/// Errors returned by the safe Rust wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `r` was not a valid scalar in the secp256k1 group (1 <= r < n).
    InvalidR,
    /// `s` was not a valid scalar in the secp256k1 group (1 <= s < n).
    InvalidS,
    /// `v` (recovery id) was not 0 or 1.
    InvalidV,
    /// Recovery produced a non-residue when computing the y-coordinate.
    NoSqrt,
    /// Recovery produced the point at infinity.
    AtInfinity,
    /// One of the input buffers was unexpectedly NULL or wrongly sized.
    BadInput,
    /// Unknown status code returned by the C-ABI; treated as a bug.
    Unknown(c_int),
}

impl Error {
    fn from_status(s: c_int) -> Self {
        match Status::from_int(s) {
            Some(Status::InvalidR) => Self::InvalidR,
            Some(Status::InvalidS) => Self::InvalidS,
            Some(Status::InvalidV) => Self::InvalidV,
            Some(Status::NoSqrt) => Self::NoSqrt,
            Some(Status::AtInfinity) => Self::AtInfinity,
            Some(Status::NullArg) | Some(Status::BufferLen) => Self::BadInput,
            Some(Status::Ok) => unreachable!("Ok is not an error"),
            None => Self::Unknown(s),
        }
    }
}

extern "C" {
    /// Recover the 64-byte uncompressed public key (X || Y, big-endian) from
    /// `(hash, r, s, v)` where `v` is the recovery id 0 or 1.
    #[link_name = "lux_secp256k1_ecrecover"]
    fn lux_secp256k1_ecrecover(
        hash: *const u8,
        r: *const u8,
        s: *const u8,
        v: u8,
        pubkey: *mut u8,
    ) -> c_int;

    /// Batch ecrecover. `inputs` is `n * 97` bytes (`hash || r || s || v`).
    /// `pubkey_out` is `n * 64` bytes; `status_out` is `n` bytes.
    #[link_name = "lux_secp256k1_ecrecover_batch"]
    fn lux_secp256k1_ecrecover_batch(
        inputs: *const u8,
        n: usize,
        pubkey_out: *mut u8,
        status_out: *mut u8,
    ) -> c_int;
}

/// Length of the keccak256 hash input to ecrecover.
pub const HASH_LEN: usize = 32;
/// Length of the 256-bit `r` and `s` ECDSA components.
pub const SCALAR_LEN: usize = 32;
/// Length of an uncompressed public key (X || Y, no 0x04 prefix).
pub const PUBKEY_LEN: usize = 64;
/// Width of one batch ecrecover input record (`hash || r || s || v`).
pub const BATCH_INPUT_STRIDE: usize = HASH_LEN + 2 * SCALAR_LEN + 1;

/// Recover the 64-byte uncompressed public key from `(hash, r, s, v)`.
///
/// `v` must be the EIP-155 recovery id 0 or 1 (i.e. not the legacy 27/28).
/// On success the public key is the concatenation X (32 bytes) || Y (32 bytes)
/// without the SEC1 `0x04` prefix.
pub fn ecrecover(
    hash: &[u8; HASH_LEN],
    r: &[u8; SCALAR_LEN],
    s: &[u8; SCALAR_LEN],
    v: u8,
) -> Result<[u8; PUBKEY_LEN], Error> {
    let mut out = [0u8; PUBKEY_LEN];
    // SAFETY: All pointers are valid for the call's duration; v is a copy.
    let rc = unsafe {
        lux_secp256k1_ecrecover(hash.as_ptr(), r.as_ptr(), s.as_ptr(), v, out.as_mut_ptr())
    };
    if rc == 0 {
        Ok(out)
    } else {
        Err(Error::from_status(rc))
    }
}

/// Batch ecrecover.
///
/// `inputs` must contain `n` records of [`BATCH_INPUT_STRIDE`] bytes each,
/// laid out as `hash || r || s || v`. Returns `Ok((pubkeys, statuses))`
/// where `pubkeys` is `n * 64` bytes and `statuses[i]` is the per-record
/// success status (`0` is success).
///
/// The function returns `Err` only if the C-ABI call itself fails; per-record
/// failures appear in the `statuses` vector.
pub fn ecrecover_batch(inputs: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if inputs.len() % BATCH_INPUT_STRIDE != 0 {
        return Err(Error::BadInput);
    }
    let n = inputs.len() / BATCH_INPUT_STRIDE;
    let mut pubkeys = vec![0u8; n * PUBKEY_LEN];
    let mut statuses = vec![0u8; n];
    // SAFETY: We have shown the buffers are sized to the C-ABI contract.
    let rc = unsafe {
        lux_secp256k1_ecrecover_batch(
            inputs.as_ptr(),
            n,
            pubkeys.as_mut_ptr(),
            statuses.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Ok((pubkeys, statuses))
    } else {
        Err(Error::from_status(rc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_from_int_round_trip() {
        for v in 0..=7 {
            assert!(Status::from_int(v).is_some());
        }
        assert!(Status::from_int(99).is_none());
    }

    #[test]
    fn batch_input_stride_is_correct() {
        assert_eq!(BATCH_INPUT_STRIDE, 97);
    }
}
