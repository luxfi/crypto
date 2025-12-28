// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-sha256.
//
// All vectors are FIPS 180-4 SHA-256 — independently verified against the
// NIST CAVS test vectors and OpenSSL `sha256sum` reference output.
//
// Sources:
//   - FIPS 180-4 (NIST, 2015) Appendix B "SHA-256 Examples"
//   - NIST CAVS (Cryptographic Algorithm Validation Program) test vectors
//   - RFC 6234 §8.5 (SHA-256 known values)

use lux_crypto_sha256::{hash, hash_into, DIGEST_LEN};

fn from_hex(s: &str) -> [u8; DIGEST_LEN] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * DIGEST_LEN);
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
    // FIPS 180-4 / RFC 6234: SHA-256("") = e3b0c44...
    let want = from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash(b""), want);
}

#[test]
fn abc() {
    // FIPS 180-4 Appendix B.1
    let want = from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hash(b"abc"), want);
}

#[test]
fn alphabet_56_bytes() {
    // FIPS 180-4 Appendix B.2: 56-byte (one 64-byte block boundary minus 8)
    let want = from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(
        hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        want
    );
}

#[test]
fn one_million_a() {
    // RFC 6234 §8.5: one-million repetitions of "a"
    let want = from_hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    let input = vec![b'a'; 1_000_000];
    assert_eq!(hash(&input), want);
}

#[test]
fn single_zero_byte() {
    // Computed via OpenSSL: echo -n -e '\x00' | openssl dgst -sha256
    let want = from_hex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    assert_eq!(hash(&[0u8]), want);
}

#[test]
fn thirty_two_zero_bytes() {
    // Block-size minus 32; common edge case in EVM contracts.
    let want = from_hex("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    assert_eq!(hash(&[0u8; 32]), want);
}

#[test]
fn fifty_five_byte_padding_boundary() {
    // 55 bytes: just below the boundary that forces a second block for padding.
    // SHA-256 padding is 1 byte 0x80 + zero-padding + 8-byte length, so 64 - 9
    // = 55 is the largest input that fits in a single 64-byte compression block.
    let want = from_hex("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    assert_eq!(hash(&[b'a'; 55]), want);
}

#[test]
fn fifty_six_byte_padding_boundary() {
    // 56 bytes: forces a second compression block.
    let want = from_hex("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    assert_eq!(hash(&[b'a'; 56]), want);
}

#[test]
fn ethereum_empty_storage_slot_hash() {
    // SHA-256 of 32 zero bytes — used as a sanity check across implementations.
    let want = from_hex("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    assert_eq!(hash(&[0u8; 32]), want);
}

#[test]
fn deterministic_across_calls() {
    let a = hash(b"test input");
    let b = hash(b"test input");
    assert_eq!(a, b);
}

#[test]
fn hash_into_matches_hash() {
    let mut buf = [0u8; DIGEST_LEN];
    let r = hash_into(b"hello world", &mut buf);
    assert_eq!(*r, hash(b"hello world"));
}

#[test]
fn long_input_two_thousand_forty_eight_bytes() {
    // Multi-block stress: 2048 bytes of incrementing values.
    let mut input = vec![0u8; 2048];
    for (i, b) in input.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    // Computed via OpenSSL.
    let want = from_hex("10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08");
    assert_eq!(hash(&input), want);
}
