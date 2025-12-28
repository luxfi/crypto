// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// FIPS 180-4 SHA-256 known-answer tests. Vectors below are the standard NIST
// CAVS vectors used by every reference implementation (OpenSSL, Bouncy Castle,
// Python hashlib).

use lux_crypto_sha256::{hash, hash_into, DIGEST_LEN};

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
    // FIPS 180-4 reference for the empty input.
    let want = from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash(b""), want);
}

#[test]
fn abc() {
    // FIPS 180-4 §A.1 known-answer test.
    let want = from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hash(b"abc"), want);
}

#[test]
fn long_message_448_bits() {
    // FIPS 180-4 §A.2 known-answer test.
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let want = from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(hash(input), want);
}

#[test]
fn one_million_a() {
    // FIPS 180-4 §A.3 long-message stress vector.
    let input = vec![b'a'; 1_000_000];
    let want = from_hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    assert_eq!(hash(&input), want);
}

#[test]
fn hash_into_is_equivalent_to_hash() {
    let mut buf = [0u8; DIGEST_LEN];
    hash_into(b"abc", &mut buf);
    assert_eq!(buf, hash(b"abc"));
}

#[test]
fn deterministic_across_calls() {
    let a = hash(b"deterministic test");
    let b = hash(b"deterministic test");
    assert_eq!(a, b);
}
