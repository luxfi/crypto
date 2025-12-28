// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// RIPEMD-160 known-answer tests from Dobbertin/Bosselaers/Preneel test suite
// (1996) and matched against OpenSSL test corpus.

use lux_crypto_ripemd160::{hash, DIGEST_LEN};

fn from_hex(s: &str) -> [u8; DIGEST_LEN] {
    let b = s.as_bytes();
    assert_eq!(b.len(), 2 * DIGEST_LEN);
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    let mut out = [0u8; DIGEST_LEN];
    for i in 0..DIGEST_LEN {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    out
}

#[test]
fn empty_string() {
    let want = from_hex("9c1185a5c5e9fc54612808977ee8f548b2258d31");
    assert_eq!(hash(b""), want);
}

#[test]
fn a() {
    let want = from_hex("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    assert_eq!(hash(b"a"), want);
}

#[test]
fn abc() {
    let want = from_hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    assert_eq!(hash(b"abc"), want);
}

#[test]
fn message_digest() {
    let want = from_hex("5d0689ef49d2fae572b881b123a85ffa21595f36");
    assert_eq!(hash(b"message digest"), want);
}

#[test]
fn alphabet() {
    let want = from_hex("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    assert_eq!(hash(b"abcdefghijklmnopqrstuvwxyz"), want);
}
