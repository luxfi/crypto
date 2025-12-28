// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-blake3: canonical Rust binding for the Lux BLAKE3 C-ABI.
//
// Links statically against `libblake3.a` and `libblake3_cpu.a` produced by
// `luxcpp/crypto/blake3`. The C-ABI surface declared in the canonical
// header `luxcpp/crypto/c-abi/lux_crypto.h` is:
//
//   int blake3      (const uint8_t* in, size_t in_len, uint8_t out[32]);
//   int blake3_batch(const uint8_t* const* in, const size_t* in_len, size_t n,
//                    uint8_t* out_flat);
//
// Status: the BLAKE3 C-ABI is currently a stub returning CRYPTO_ERR_NOTIMPL
// (luxcpp/crypto/blake3/c-abi/c_blake3.cpp). The Rust binding is shipped so
// downstream consumers can wire against a stable surface; tests that exercise
// real output are gated with #[ignore] and will be re-enabled when the C-ABI
// body lands. The keyed_hash / derive_key / hash_xof entry points are not
// part of the canonical C-ABI; consumers needing those should call BLAKE3
// directly from a pure-Rust crate.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn blake3(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
}

/// Length of a default BLAKE3 digest in bytes.
pub const OUT_LEN: usize = 32;

/// Errors returned by the BLAKE3 binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Underlying C-ABI call returned a non-zero status.
    InternalError(c_int),
}

/// Compute the default 32-byte BLAKE3 digest of `input`.
///
/// Returns `Err(Error::InternalError(rc))` when the underlying C-ABI returns a
/// non-zero status (e.g. CRYPTO_ERR_NOTIMPL = -5 while the body is unwired).
#[inline]
pub fn hash(input: &[u8]) -> Result<[u8; OUT_LEN], Error> {
    let mut out = [0u8; OUT_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake3(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    match rc {
        0 => Ok(out),
        other => Err(Error::InternalError(other)),
    }
}
