// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// RFC 7693 BLAKE2b-512 known-answer tests.

use lux_crypto_blake2b::{hash, DIGEST_LEN};

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
    let want = from_hex(
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
         d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    );
    assert_eq!(hash(b""), want);
}

#[test]
fn abc() {
    // RFC 7693 §F.4 reference vector for "abc".
    let want = from_hex(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
    assert_eq!(hash(b"abc"), want);
}

#[test]
fn quick_brown_fox() {
    let want = from_hex(
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673\
         f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
    );
    assert_eq!(hash(b"The quick brown fox jumps over the lazy dog"), want);
}
