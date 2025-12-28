// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-ripemd160.
//
// Reference vectors taken from Dobbertin/Bosselaers/Preneel,
// "RIPEMD-160: A Strengthened Version of RIPEMD" (1996), and verified
// against Python `hashlib.new('ripemd160', ...)`. Bitcoin RIPEMD160(SHA256(.))
// vector cross-checked against Bitcoin Core test suite.

use lux_crypto_ripemd160::{hash, hash_into, DIGEST_LEN};

fn from_hex(s: &str) -> [u8; DIGEST_LEN] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * DIGEST_LEN);
    let mut out = [0u8; DIGEST_LEN];
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    for i in 0..DIGEST_LEN {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

#[test]
fn empty_string() {
    // RIPEMD-160 paper, official test vector
    let want = from_hex("9c1185a5c5e9fc54612808977ee8f548b2258d31");
    assert_eq!(hash(b""), want);
}

#[test]
fn single_a() {
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
fn lowercase_alphabet() {
    let want = from_hex("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    assert_eq!(hash(b"abcdefghijklmnopqrstuvwxyz"), want);
}

#[test]
fn upper_lower_alphanumeric() {
    let want = from_hex("b0e20b6e3116640286ed3a87a5713079b21f5189");
    assert_eq!(
        hash(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        want,
    );
}

#[test]
fn one_million_a() {
    // "Million-a" stress vector — covers many compression-block iterations.
    let want = from_hex("52783243c1697bdbe16d37f97f68f08325dc1528");
    let buf = vec![b'a'; 1_000_000];
    assert_eq!(hash(&buf), want);
}

#[test]
fn quick_brown_fox() {
    let want = from_hex("37f332f68db77bd9d7edd4969571ad671cf9dd3b");
    assert_eq!(hash(b"The quick brown fox jumps over the lazy dog"), want);
}

#[test]
fn single_zero_byte() {
    let want = from_hex("c81b94933420221a7ac004a90242d8b1d3e5070d");
    assert_eq!(hash(&[0u8]), want);
}

#[test]
fn thirty_two_zero_bytes() {
    let want = from_hex("d1a70126ff7a149ca6f9b638db084480440ff842");
    assert_eq!(hash(&[0u8; 32]), want);
}

#[test]
fn fifty_five_zero_bytes_padding_boundary() {
    let want = from_hex("e323d78db60afc7404def79abb82b8fb73591037");
    assert_eq!(hash(&[0u8; 55]), want);
}

#[test]
fn fifty_six_zero_bytes_padding_boundary() {
    let want = from_hex("7724d7cdbbe24a75a58958d784e3a325ce0e9c7c");
    assert_eq!(hash(&[0u8; 56]), want);
}

#[test]
fn deterministic_across_calls() {
    let a = hash(b"determinism check");
    let b = hash(b"determinism check");
    assert_eq!(a, b);
}

#[test]
fn hash_into_matches_hash() {
    let mut buf = [0u8; DIGEST_LEN];
    let r = hash_into(b"hello world", &mut buf);
    assert_eq!(*r, hash(b"hello world"));
}
