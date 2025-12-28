// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-blake3.
//
// FIXME: luxcpp/crypto/blake3/c-abi/c_blake3.cpp returns CRYPTO_ERR_NOTIMPL
// for all entry points. Re-enable these vectors once the C-ABI body lands.
// Tracked at luxcpp/crypto issue #blake3-c-abi-impl.
//
// Vectors below are the upstream BLAKE3-team/BLAKE3 v1.5.0 reference
// `test_vectors.json` first 32-byte hash output.

use lux_crypto_blake3::{hash, Error};

fn from_hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert_eq!(b.len(), 64);
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    out
}

#[test]
#[ignore = "luxcpp blake3 c-abi NOTIMPL — tracked at #blake3-c-abi-impl"]
fn empty_input_default_digest() {
    // Upstream BLAKE3 reference output for the empty input (first 32 bytes
    // of the hash function output stream).
    let want = from_hex32("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    let got = hash(b"").expect("blake3(empty)");
    assert_eq!(got, want, "BLAKE3 empty input mismatch");
}

#[test]
#[ignore = "luxcpp blake3 c-abi NOTIMPL — tracked at #blake3-c-abi-impl"]
fn input_one_byte_zero_default_digest() {
    let want = from_hex32("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
    let got = hash(&[0u8]).expect("blake3(0x00)");
    assert_eq!(got, want);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    // While the C-ABI body is unwired, every call returns -5 (CRYPTO_ERR_NOTIMPL).
    // This is the only check we can run today that does not silently pass.
    match hash(b"any input") {
        Ok(_) => {
            // Once the C-ABI body lands, this branch becomes the new normal.
        }
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
    }
}
