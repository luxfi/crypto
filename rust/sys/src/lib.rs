// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Raw FFI bindings to luxcpp/crypto.
//
// Phase 1 surface: secp256k1 ECDSA public-key recovery.
//
// All multi-byte buffers are big-endian. The C ABI is documented in
// `luxcpp/crypto/include/lux/crypto/secp256k1.h`. Symbols are brand-neutral.

#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::c_int;

/// Status codes returned by the secp256k1 C ABI.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secp256k1Status {
    Ok = 0,
    InvalidR = 1,
    InvalidS = 2,
    InvalidV = 3,
    NoSqrt = 4,
    AtInfinity = 5,
    NullArg = 6,
    BufferLen = 7,
}

impl Secp256k1Status {
    /// Convert a raw C `c_int` from a libcrypto secp256k1 call to the typed enum.
    /// Returns `None` for unknown values; callers can treat that as a bug.
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

extern "C" {
    /// Recover the 64-byte uncompressed public key from (hash, r, s, v).
    /// Returns one of the `Secp256k1Status` codes as `c_int`.
    pub fn secp256k1_ecrecover(
        hash: *const u8,
        r: *const u8,
        s: *const u8,
        v: u8,
        pubkey: *mut u8,
    ) -> c_int;

    /// Batch ecrecover. inputs is n * 97 bytes (hash || r || s || v).
    /// pubkey_out is n * 64 bytes; status_out is n bytes.
    pub fn secp256k1_ecrecover_batch(
        inputs: *const u8,
        n: usize,
        pubkey_out: *mut u8,
        status_out: *mut u8,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    // Compile-time symbol check; the actual smoke test is in luxfi/accel
    // (Go side) and the C++ test harness.
    #[test]
    fn link() {
        let _f: unsafe extern "C" fn(*const u8, *const u8, *const u8, u8, *mut u8) -> i32 =
            super::secp256k1_ecrecover;
    }

    #[test]
    fn status_from_int() {
        assert_eq!(super::Secp256k1Status::from_int(0), Some(super::Secp256k1Status::Ok));
        assert_eq!(super::Secp256k1Status::from_int(7), Some(super::Secp256k1Status::BufferLen));
        assert_eq!(super::Secp256k1Status::from_int(99), None);
    }
}
