// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// RIPEMD-160 KAT vectors (Dobbertin/Bosselaers/Preneel 1996 reference set).

use lux_crypto_ripemd160::{hash, DIGEST_LEN};

fn from_hex(s: &str) -> [u8; DIGEST_LEN] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * DIGEST_LEN);
    let mut out = [0u8; DIGEST_LEN];
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("non-hex byte"),
    };
    for i in 0..DIGEST_LEN {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

#[test]
fn empty_string() {
    // RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    let want = from_hex("9c1185a5c5e9fc54612808977ee8f548b2258d31");
    assert_eq!(hash(b""), want);
}

#[test]
fn abc() {
    // RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
    let want = from_hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    assert_eq!(hash(b"abc"), want);
}
