// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-keccak: canonical Rust binding for the Lux keccak256 C-ABI.
//
// Links statically against `libkeccak_cpu.a` produced by `luxcpp/crypto/keccak`.
// The C-ABI is declared in `luxcpp/crypto/include/lux/crypto/keccak.h` and is
// the unkeyed Keccak-f[1600] sponge with the original NIST submission padding
// (rate=1088, capacity=512, output=256 bits) used by Ethereum and the EVM.
//
// This is *not* SHA3-256: SHA3 uses the FIPS 202 0x06 padding byte, while
// Keccak retains the original 0x01 padding byte from the SHA-3 competition.
// The reference test vector for the empty input is
// `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern "C" {
    /// keccak256 over `input_len` bytes at `input`, writing 32 bytes at `output`.
    ///
    /// The C-ABI declaration in `lux/crypto/keccak.h` returns `void`; we mirror
    /// that exactly. Caller must guarantee `output` points to at least 32
    /// writable bytes.
    #[link_name = "lux_keccak256"]
    fn lux_keccak256(input: *const u8, input_len: usize, output: *mut u8);
}

/// Length of a keccak256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Compute the keccak256 digest of `input`.
///
/// This is the Ethereum keccak (original Keccak-f[1600] padding `0x01`),
/// not SHA3-256.
#[inline]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: `input.as_ptr()` is valid for `input.len()` bytes (read-only)
    // and `out.as_mut_ptr()` is valid for `DIGEST_LEN` bytes (write).
    unsafe {
        lux_keccak256(input.as_ptr(), input.len(), out.as_mut_ptr());
    }
    out
}

/// Compute the keccak256 digest of `input` into a caller-supplied buffer.
///
/// Returns the same byte slice for ergonomic chaining.
#[inline]
pub fn hash_into<'a>(input: &[u8], output: &'a mut [u8; DIGEST_LEN]) -> &'a [u8; DIGEST_LEN] {
    // SAFETY: pointers are valid for the durations of the call.
    unsafe {
        lux_keccak256(input.as_ptr(), input.len(), output.as_mut_ptr());
    }
    output
}
