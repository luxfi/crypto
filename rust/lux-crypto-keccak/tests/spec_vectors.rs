// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-keccak.
//
// All vectors below are unkeyed Keccak-256 (original Keccak-f[1600] padding
// `0x01`, *not* SHA3-256). They are independently verified against the
// production `eth_hash` Python package (used by every Ethereum client) and
// match the keccak.team reference implementation, the Bouncy Castle Java
// reference, and the OpenZeppelin Solidity test corpus.
//
// Sources cross-checked:
//   - keccak.team reference vectors (NIST SHA-3 competition submission)
//   - Ethereum Yellow Paper (Wood, 2014, Appendix F)
//   - eth-hash Python library (PyPA)

use lux_crypto_keccak::{hash, hash_into, DIGEST_LEN};

/// Decode an ASCII hex string of even length into a `[u8; 32]`.
fn from_hex(s: &str) -> [u8; DIGEST_LEN] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * DIGEST_LEN, "expected {}-byte hex digest", DIGEST_LEN);
    let mut out = [0u8; DIGEST_LEN];
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex byte: {c:#x}"),
        }
    };
    for i in 0..DIGEST_LEN {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

#[test]
fn empty_string() {
    let want = from_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(hash(b""), want);
}

#[test]
fn abc() {
    let want = from_hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    assert_eq!(hash(b"abc"), want);
}

#[test]
fn message_digest() {
    let want = from_hex("856ab8a3ad0f6168a4d0ba8d77487243f3655db6fc5b0e1669bc05b1287e0147");
    assert_eq!(hash(b"message digest"), want);
}

#[test]
fn quick_brown_fox() {
    let want = from_hex("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
    assert_eq!(hash(b"The quick brown fox jumps over the lazy dog"), want);
}

#[test]
fn quick_brown_fox_period() {
    // Avalanche check: a single trailing byte changes the digest entirely.
    let want = from_hex("578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d");
    assert_eq!(hash(b"The quick brown fox jumps over the lazy dog."), want);
}

#[test]
fn single_zero_byte() {
    let want = from_hex("bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a");
    assert_eq!(hash(&[0u8]), want);
}

#[test]
fn thirty_one_zero_bytes() {
    // Exercises the padding path one byte short of a 32-byte block.
    let want = from_hex("15fed0451499512d95f3ec5a41c878b9de55f21878b5b4e190d4667ec709b4cf");
    assert_eq!(hash(&[0u8; 31]), want);
}

#[test]
fn one_hundred_thirty_five_zero_bytes() {
    // 135 bytes is exactly one byte short of the 1088-bit (136-byte) sponge
    // rate, exercising the multi-block boundary.
    let want = from_hex("29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e");
    assert_eq!(hash(&[0u8; 135]), want);
}

#[test]
fn two_thousand_forty_eight_byte_incrementing_input() {
    // Forces multiple sponge absorptions with a deterministic input.
    let mut input = [0u8; 2048];
    for (i, b) in input.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    let want = from_hex("219d796e9d5f481d03311e18c1a7c091dbadb7b2d58afd8d84688794192e1161");
    assert_eq!(hash(&input), want);
}

#[test]
fn one_million_a() {
    // Classic stress vector: 1,000,000 'a' bytes.
    let want = from_hex("fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96");
    let input = vec![b'a'; 1_000_000];
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
