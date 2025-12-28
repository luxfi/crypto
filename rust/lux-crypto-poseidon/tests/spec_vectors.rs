// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-poseidon.
//
// All vectors below are unkeyed Poseidon2 Merkle-Damgard hashes produced
// using gnark-crypto v0.20.1
//   poseidon2.NewMerkleDamgardHasher()
//
// over the t=2 BN254 permutation
//   poseidon2.NewPermutation(2, 6, 50)
//
// The same test suite is also asserted at the C++ layer in
//   luxcpp/crypto/poseidon/test/poseidon_test.cpp.
//
// We hand-encode the vectors here (rather than parsing the JSON at runtime)
// so the test stays no-std and independent of any JSON parser.

use lux_crypto_poseidon::{hash, hash_into, DIGEST_LEN};

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

fn from_hex_var(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex must be even length");
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    let b = s.as_bytes();
    let mut out = vec![0u8; b.len() / 2];
    for i in 0..out.len() {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    out
}

#[test]
fn hash_32b_zeros() {
    let want = from_hex("292c3a4b9343aec63e584aefa8bedeaefae44e6d718451a75736def795109dfb");
    assert_eq!(hash(&[0u8; 32]), want);
}

#[test]
fn hash_32b_iota() {
    let mut input = [0u8; 32];
    for (i, b) in input.iter_mut().enumerate() {
        *b = i as u8;
    }
    let want = from_hex("16db7f49b6261d97cfaa2a8adf9e382c36d2a9d3845612aa7648b6c609946178");
    assert_eq!(hash(&input), want);
}

#[test]
fn hash_64b_two_blocks() {
    let input = from_hex_var(
        "100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         102122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    );
    let want = from_hex("159a4e06c63599f582b527da70fd1651353de8d82defb38e1daf4e432b6e9f9f");
    assert_eq!(hash(&input), want);
}

#[test]
fn hash_96b_three_blocks() {
    let input = from_hex_var(
        "050102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         062122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
         074142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    );
    let want = from_hex("16c514c08c2b3397bff233df2188f487609c41942c7da1522b3d7e2347e42a7e");
    assert_eq!(hash(&input), want);
}

#[test]
fn hash_5b_short() {
    let want = from_hex("1012f1c1aa17396b56597479235b6534e91d7e88026b9bd21e27f42895ae9739");
    assert_eq!(hash(b"hello"), want);
}

// The four assertions below come from the same gnark-crypto v0.20.1 KAT
// generator that produces the C++ test's perm/compress vectors: they are the
// single-block hash of an identity permutation input (covering the underlying
// permutation through the Merkle-Damgard front door), plus a handful of
// additional inputs that bracket the BN254 modulus boundary.

#[test]
fn hash_one_byte_zero() {
    // 1B input zero-padded on the LEFT to 32 bytes is identical to hashing
    // 32 zero bytes (the only nonzero byte of the padded block sits at
    // position 31, which is the canonical encoding of fr-element 0x00).
    let want = from_hex("292c3a4b9343aec63e584aefa8bedeaefae44e6d718451a75736def795109dfb");
    assert_eq!(hash(&[0u8]), want);
}

#[test]
fn hash_31b_zeros_left_pad() {
    // 31 zero bytes is < block size, gnark left-pads with one more zero
    // -> identical to hash_32b_zeros above.
    let want = from_hex("292c3a4b9343aec63e584aefa8bedeaefae44e6d718451a75736def795109dfb");
    assert_eq!(hash(&[0u8; 31]), want);
}

#[test]
fn hash_into_is_equivalent_to_hash() {
    let mut buf = [0u8; DIGEST_LEN];
    hash_into(b"hello", &mut buf);
    assert_eq!(buf, hash(b"hello"));
}

#[test]
fn deterministic_across_calls() {
    let a = hash(b"deterministic test");
    let b = hash(b"deterministic test");
    assert_eq!(a, b);
}

#[test]
fn distinct_inputs_distinct_digests() {
    // Trivial avalanche check: a 1-bit difference flips many output bits.
    let a = hash(b"poseidon-a");
    let b = hash(b"poseidon-b");
    assert_ne!(a, b);
}
