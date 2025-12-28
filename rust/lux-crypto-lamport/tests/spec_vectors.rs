// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-lamport.
//
// Vectors taken from luxfi/crypto/lamport/kat_vectors_test.go (the canonical
// Go-layer KAT). Each entry pins (seed, msg) -> (PK digest, signature digest)
// where the digest is SHA-256(pk||...) and SHA-256(sig||...). The C-ABI body
// in luxcpp/crypto/lamport/cpp/lamport.cpp is byte-equal to the Go body for
// the same seed; this test confirms the Rust binding preserves that
// invariant.

use lux_crypto_lamport::{
    keygen, sign, verify, MSG_HASH_LEN, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN,
};

fn from_hex_n<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * N);
    let mut out = [0u8; N];
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    for i in 0..N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

/// Compute SHA-256 of `data` using the standard library-equivalent SHA-256.
/// We avoid bringing a Rust SHA-256 dep by using the Lux SHA-256 binding
/// already in the workspace.
fn sha256(data: &[u8]) -> [u8; 32] {
    lux_crypto_sha256::hash(data)
}

struct Vector {
    seed: &'static str,
    msg: &'static str,
    pk_digest: &'static str,
    sig_digest: &'static str,
}

// 10 vectors copied verbatim from
// /Users/z/work/lux/crypto/lamport/kat_vectors_test.go
const VECTORS: &[Vector] = &[
    Vector {
        seed: "0000000000000000000000000000000000000000000000000000000000000000",
        msg: "0000000000000000000000000000000000000000000000000000000000000000",
        pk_digest: "658289ca23845d39f852b5c006225f47883334e2a9f3c33909e6d651acf0dcbb",
        sig_digest: "2b3f42653f0812929ba097b9f5f5fb6764731334d31f64ccf4a325aab8e6588b",
    },
    Vector {
        seed: "0001020304050607080910111213141516171819202122232425262728293031",
        msg: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        pk_digest: "68464ad0fe673398f540c2377cb59011014ac6768f70f1eee7feffd7955c6509",
        sig_digest: "5a1ff37e637238381fdd3fe095178893d93eb05a97103d137b5c25c2c1ab6377",
    },
    Vector {
        seed: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        msg: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        pk_digest: "8bd4d4f9f97c3572b703ffa55ea5247ef9cc6326a055859f899e5fd02ccd26c3",
        sig_digest: "88f9d7fb57d1eb14b5de17f0b595c3edc71247b7c3ba45f4b76335a434a0bbf4",
    },
    Vector {
        seed: "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
        msg: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        pk_digest: "ecfef2a053f3dd22be3ce801f3aa5265cd82423e89d83418db6b3eea62a35e01",
        sig_digest: "d18de637fc9401ab7af40570936fb26c64761f4e32840cc5cf41c746654cc165",
    },
    Vector {
        seed: "a1b2c3d4e5f6071829304152637485960a1b2c3d4e5f6071829304152637485a",
        msg: "deadbeefcafe000011223344556677889900aabbccddeeff0011223344556677",
        pk_digest: "5ccada23bb59d921dbb2bad0807d90eab9a5cb9b29a1c1ffc71cbad5eea020ee",
        sig_digest: "c7f886196739ba568fd8795efdd5bd0b5a58709ac90c067e77848933855012a6",
    },
    Vector {
        seed: "1111111122222222333333334444444455555555666666667777777788888888",
        msg: "55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa",
        pk_digest: "f0980a7313f11b960ff43a3c5d5a70726ed414046ddc1fb0cdddc97b81ecb5cd",
        sig_digest: "70e95dd6c45c726a9e4d40a5cdb4edce964decdc4a4cbe183477e49c61725001",
    },
    Vector {
        seed: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        msg: "7777777777777777777777777777777777777777777777777777777777777777",
        pk_digest: "1333b2c0deb2c9f00d66d2dbbcbdd4665d5e632537c5265071bab54b4f3a5939",
        sig_digest: "fa1b0c17d0d8ef412f0a4632842f49be1ff420b4d3a41ed769aaaa327d58d567",
    },
    Vector {
        seed: "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
        msg: "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        pk_digest: "92abab102a1d5314c5c3c8de43c1a9f8e2137591b4825dc7e39571b62c92b194",
        sig_digest: "df7618f8332dbb888cf37d8036158f68fc58795328fc31ceb2801acb1a571581",
    },
    Vector {
        seed: "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
        msg: "f0e1d2c3b4a5968778695a4b3c2d1e0f102030405060708090a0b0c0d0e0f000",
        pk_digest: "674ac393d641369a09fbb273cab1ac24278d12ae60f24f736399c837d08e0cbe",
        sig_digest: "33dd50e08ae250b595d0ed397ce7f3cd0d3088f56c0f73a529a1a1996e23fd2d",
    },
    Vector {
        seed: "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
        msg: "3141592653589793238462643383279502884197169399375105820974944592",
        pk_digest: "9ebc6e218bcd0dbbb5c1fe47489df876789a335ae2c2fb708da54200484264f5",
        sig_digest: "a736269e4a760b122fabdd48fdaa0b86d91aa97c0b6953e60203c8ae6f90319f",
    },
];

#[test]
fn kat_vectors_byte_equal_pk_and_signature_digests() {
    for (i, v) in VECTORS.iter().enumerate() {
        let seed: [u8; SEED_LEN] = from_hex_n(v.seed);
        let msg: [u8; MSG_HASH_LEN] = from_hex_n(v.msg);
        let want_pk_digest: [u8; 32] = from_hex_n(v.pk_digest);
        let want_sig_digest: [u8; 32] = from_hex_n(v.sig_digest);

        let (pk, sk) = keygen(&seed).expect("keygen must succeed");
        let pk_digest = sha256(&pk[..]);
        assert_eq!(
            pk_digest, want_pk_digest,
            "vector {i}: PK digest mismatch (seed {})", v.seed,
        );

        let sig = sign(&sk, &msg).expect("sign must succeed");
        let sig_digest = sha256(&sig[..]);
        assert_eq!(
            sig_digest, want_sig_digest,
            "vector {i}: signature digest mismatch (seed {})", v.seed,
        );

        verify(&pk, &msg, &sig).expect("self-verify must succeed");
    }
}

#[test]
fn tampered_signature_fails_verify() {
    let seed: [u8; SEED_LEN] = from_hex_n(VECTORS[0].seed);
    let msg: [u8; MSG_HASH_LEN] = from_hex_n(VECTORS[0].msg);
    let (pk, sk) = keygen(&seed).unwrap();
    let mut sig = sign(&sk, &msg).unwrap();
    // Flip a bit in the first signature element.
    sig[0] ^= 0x01;
    assert!(verify(&pk, &msg, &sig).is_err());
}

#[test]
fn signature_doesnt_verify_against_different_message() {
    let seed: [u8; SEED_LEN] = from_hex_n(VECTORS[1].seed);
    let msg: [u8; MSG_HASH_LEN] = from_hex_n(VECTORS[1].msg);
    let other_msg: [u8; MSG_HASH_LEN] = from_hex_n(VECTORS[2].msg);
    let (pk, sk) = keygen(&seed).unwrap();
    let sig = sign(&sk, &msg).unwrap();
    assert!(verify(&pk, &other_msg, &sig).is_err());
}

#[test]
fn signature_doesnt_verify_against_different_keypair() {
    let seed_a: [u8; SEED_LEN] = from_hex_n(VECTORS[3].seed);
    let seed_b: [u8; SEED_LEN] = from_hex_n(VECTORS[4].seed);
    let msg: [u8; MSG_HASH_LEN] = from_hex_n(VECTORS[3].msg);
    let (_pk_a, sk_a) = keygen(&seed_a).unwrap();
    let (pk_b, _sk_b) = keygen(&seed_b).unwrap();
    let sig_a = sign(&sk_a, &msg).unwrap();
    assert!(verify(&pk_b, &msg, &sig_a).is_err());
}

#[test]
fn signature_size_constants_match_spec() {
    assert_eq!(PUBLIC_KEY_LEN, 16384);
    assert_eq!(SIGNATURE_LEN, 8192);
}
