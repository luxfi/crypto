// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-blake3: canonical Rust binding for the Lux BLAKE3 C-ABI.
//
// Links statically against `libblake3.a` and `libblake3_cpu.a` produced by
// `luxcpp/crypto/blake3`, whose CPU body is the vendored BLAKE3 reference C
// (BLAKE3-team/BLAKE3 v1.5.0, portable-only). All four canonical BLAKE3
// modes are exposed:
//
//   * `hash`         -- default-length (32-byte) hash, no key
//   * `keyed_hash`   -- 32-byte hash with 32-byte key (RFC-style MAC)
//   * `derive_key`   -- context-string-bound 32-byte derivation
//   * `hash_xof`     -- extensible-length output (XOF)
//
// Byte-equal to upstream b3sum / blake3-py.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int};

extern "C" {
    fn blake3(input: *const u8, input_len: usize, output: *mut u8) -> c_int;
    fn lux_blake3_keyed(
        key: *const u8,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
    ) -> c_int;
    fn lux_blake3_derive_key(
        context: *const c_char,
        key_material: *const u8,
        key_material_len: usize,
        output: *mut u8,
    ) -> c_int;
    fn lux_blake3_xof(
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_len: usize,
    ) -> c_int;
}

/// Length of a default BLAKE3 digest in bytes.
pub const OUT_LEN: usize = 32;
/// Length of a BLAKE3 key in bytes (for `keyed_hash`).
pub const KEY_LEN: usize = 32;

/// Compute the default 32-byte BLAKE3 digest of `input`.
#[inline]
pub fn hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut out = [0u8; OUT_LEN];
    // SAFETY: pointers valid for the call's duration; output sized to digest.
    let rc = unsafe { blake3(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    debug_assert_eq!(rc, 0, "blake3 returned non-zero status: {}", rc);
    out
}

/// Compute the keyed BLAKE3 digest (MAC) of `input` under `key`.
#[inline]
pub fn keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; OUT_LEN] {
    let mut out = [0u8; OUT_LEN];
    // SAFETY: pointers valid for the call's duration; key/output sized exactly.
    let rc = unsafe {
        lux_blake3_keyed(
            key.as_ptr(),
            input.as_ptr(),
            input.len(),
            out.as_mut_ptr(),
        )
    };
    debug_assert_eq!(rc, 0, "blake3 keyed_hash returned non-zero status: {}", rc);
    out
}

/// Derive a 32-byte sub-key from `key_material` bound to a NUL-terminated
/// ASCII `context` string.
///
/// `context_z` MUST contain a trailing NUL byte (`b"...\0"`). This binds the
/// derivation to a hardcoded application-context literal per the BLAKE3 spec.
#[inline]
pub fn derive_key(context_z: &[u8], key_material: &[u8]) -> [u8; OUT_LEN] {
    debug_assert!(
        context_z.last() == Some(&0),
        "derive_key context must be NUL-terminated"
    );
    let mut out = [0u8; OUT_LEN];
    // SAFETY: pointers valid for the call's duration; context is NUL-terminated.
    let rc = unsafe {
        lux_blake3_derive_key(
            context_z.as_ptr() as *const c_char,
            key_material.as_ptr(),
            key_material.len(),
            out.as_mut_ptr(),
        )
    };
    debug_assert_eq!(
        rc, 0,
        "blake3 derive_key returned non-zero status: {}",
        rc
    );
    out
}

/// Extensible-output BLAKE3. `output` may be any length; the result is the
/// prefix of the BLAKE3 root output keystream of that length.
#[inline]
pub fn hash_xof(input: &[u8], output: &mut [u8]) {
    // SAFETY: pointers valid for the call's duration.
    let rc = unsafe {
        lux_blake3_xof(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    debug_assert_eq!(rc, 0, "blake3 hash_xof returned non-zero status: {}", rc);
}
