// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Raw FFI bindings to luxcpp/crypto.
//
// Phase 1 surface: secp256k1 ECDSA public-key recovery.
//
// All multi-byte buffers are big-endian. The C ABI is documented in
// `luxcpp/crypto/include/lux/crypto/secp256k1.h`.

#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::ffi::c_int;

pub const LUX_SECP256K1_OK: c_int = 0;
pub const LUX_SECP256K1_ERR_INVALID_R: c_int = 1;
pub const LUX_SECP256K1_ERR_INVALID_S: c_int = 2;
pub const LUX_SECP256K1_ERR_INVALID_V: c_int = 3;
pub const LUX_SECP256K1_ERR_NO_SQRT: c_int = 4;
pub const LUX_SECP256K1_ERR_AT_INFINITY: c_int = 5;
pub const LUX_SECP256K1_ERR_NULL_ARG: c_int = 6;
pub const LUX_SECP256K1_ERR_BUFFER_LEN: c_int = 7;

extern "C" {
    /// Recover the 64-byte uncompressed public key from (hash, r, s, v).
    /// Returns one of the LUX_SECP256K1_* status codes.
    pub fn lux_secp256k1_ecrecover(
        hash: *const u8,
        r: *const u8,
        s: *const u8,
        v: u8,
        pubkey: *mut u8,
    ) -> c_int;

    /// Batch ecrecover. inputs is n * 97 bytes (hash || r || s || v).
    /// pubkey_out is n * 64 bytes; status_out is n bytes.
    pub fn lux_secp256k1_ecrecover_batch(
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
            super::lux_secp256k1_ecrecover;
    }
}
