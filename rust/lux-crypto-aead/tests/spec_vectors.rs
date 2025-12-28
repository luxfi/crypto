// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-aead: ChaCha20-Poly1305 AEAD
// per RFC 8439.
//
// Reference vectors:
//   - RFC 8439 §2.8.2 "Example and Test Vector for AEAD_CHACHA20_POLY1305"
//   - RFC 8439 Appendix A.5 (alternate Poly1305 tag from the same construct)
//   - libsodium `crypto_aead_chacha20poly1305_ietf_encrypt` test corpus

use lux_crypto_aead::{open, seal, KEY_LEN, NONCE_LEN, TAG_LEN};

fn from_hex(s: &str) -> Vec<u8> {
    let s = s.as_bytes();
    assert!(s.len() % 2 == 0, "hex string must have even length");
    let mut out = Vec::with_capacity(s.len() / 2);
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    for i in (0..s.len()).step_by(2) {
        out.push((nibble(s[i]) << 4) | nibble(s[i + 1]));
    }
    out
}

fn fixed_key(s: &str) -> [u8; KEY_LEN] {
    let v = from_hex(s);
    assert_eq!(v.len(), KEY_LEN);
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&v);
    k
}

fn fixed_nonce(s: &str) -> [u8; NONCE_LEN] {
    let v = from_hex(s);
    assert_eq!(v.len(), NONCE_LEN);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&v);
    n
}

fn fixed_tag(s: &str) -> [u8; TAG_LEN] {
    let v = from_hex(s);
    assert_eq!(v.len(), TAG_LEN);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&v);
    t
}

#[test]
fn rfc_8439_section_2_8_2_seal() {
    // RFC 8439 §2.8.2 — canonical AEAD test vector.
    let key = fixed_key(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    let nonce = fixed_nonce("070000004041424344454647");
    let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: \
              If I could offer you only one tip for the future, sunscreen would be it.";

    let want_ct = from_hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let want_tag =
        fixed_tag("1ae10b594f09e26a7e902ecbd0600691");

    let (ct, tag) = seal(&key, &nonce, &aad, pt).expect("seal must succeed");
    assert_eq!(ct, want_ct);
    assert_eq!(tag, want_tag);
}

#[test]
fn rfc_8439_section_2_8_2_open() {
    // Round-trip the §2.8.2 vector.
    let key = fixed_key(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    let nonce = fixed_nonce("070000004041424344454647");
    let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    let ct = from_hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let tag = fixed_tag("1ae10b594f09e26a7e902ecbd0600691");

    let pt = open(&key, &nonce, &aad, &ct, &tag).expect("open must succeed");
    assert_eq!(
        pt,
        b"Ladies and Gentlemen of the class of '99: \
         If I could offer you only one tip for the future, sunscreen would be it."
    );
}

#[test]
fn empty_plaintext_seal_open_round_trip() {
    let key = [0u8; KEY_LEN];
    let nonce = [0u8; NONCE_LEN];
    let aad: &[u8] = &[];
    let pt: &[u8] = &[];
    let (ct, tag) = seal(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), 0);
    let recovered = open(&key, &nonce, aad, &ct, &tag).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn empty_aad_round_trip_with_payload() {
    let key = fixed_key(
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let nonce = fixed_nonce("000000000000000000000000");
    let aad: &[u8] = &[];
    let pt = b"hello world";
    let (ct, tag) = seal(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), pt.len());
    let recovered = open(&key, &nonce, aad, &ct, &tag).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn tampered_ciphertext_fails_auth() {
    let key = fixed_key(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    let nonce = fixed_nonce("070000004041424344454647");
    let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99";

    let (mut ct, tag) = seal(&key, &nonce, &aad, pt).unwrap();
    // Flip a bit in the ciphertext. Must fail auth.
    ct[0] ^= 0x01;
    assert_eq!(
        open(&key, &nonce, &aad, &ct, &tag).unwrap_err(),
        lux_crypto_aead::Error::AuthFail,
    );
}

#[test]
fn tampered_tag_fails_auth() {
    let key = fixed_key(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    let nonce = fixed_nonce("070000004041424344454647");
    let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"hello world";

    let (ct, mut tag) = seal(&key, &nonce, &aad, pt).unwrap();
    tag[0] ^= 0x01;
    assert_eq!(
        open(&key, &nonce, &aad, &ct, &tag).unwrap_err(),
        lux_crypto_aead::Error::AuthFail,
    );
}

#[test]
fn tampered_aad_fails_auth() {
    let key = fixed_key(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    let nonce = fixed_nonce("070000004041424344454647");
    let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"plaintext";

    let (ct, tag) = seal(&key, &nonce, &aad, pt).unwrap();
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0x01;
    assert_eq!(
        open(&key, &nonce, &bad_aad, &ct, &tag).unwrap_err(),
        lux_crypto_aead::Error::AuthFail,
    );
}

#[test]
fn long_payload_round_trip() {
    let key = fixed_key(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    );
    let nonce = fixed_nonce("000102030405060708090a0b");
    let aad = b"AAD".as_slice();
    let pt = vec![0xAAu8; 4096];

    let (ct, tag) = seal(&key, &nonce, aad, &pt).unwrap();
    assert_eq!(ct.len(), pt.len());
    let recovered = open(&key, &nonce, aad, &ct, &tag).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn unique_keys_produce_independent_ciphertexts() {
    let nonce = fixed_nonce("000000000000000000000000");
    let aad: &[u8] = &[];
    let pt = b"deterministic";
    let key_a = fixed_key(
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let key_b = fixed_key(
        "0000000000000000000000000000000000000000000000000000000000000002",
    );
    let (ct_a, _) = seal(&key_a, &nonce, aad, pt).unwrap();
    let (ct_b, _) = seal(&key_b, &nonce, aad, pt).unwrap();
    assert_ne!(ct_a, ct_b);
}

#[test]
fn deterministic_seal_with_fixed_inputs() {
    let key = fixed_key(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    );
    let nonce = fixed_nonce("000102030405060708090a0b");
    let aad = b"hello";
    let pt = b"secret";

    let (ct1, tag1) = seal(&key, &nonce, aad, pt).unwrap();
    let (ct2, tag2) = seal(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct1, ct2);
    assert_eq!(tag1, tag2);
}

#[test]
fn cross_nonce_isolation() {
    let key = fixed_key(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    );
    let nonce_a = fixed_nonce("000102030405060708090a0b");
    let nonce_b = fixed_nonce("000102030405060708090a0c");
    let pt = b"isolation test";
    let (ct_a, tag_a) = seal(&key, &nonce_a, &[], pt).unwrap();
    let (ct_b, _tag_b) = seal(&key, &nonce_b, &[], pt).unwrap();
    assert_ne!(ct_a, ct_b);
    // Decrypt with wrong nonce must fail.
    assert!(open(&key, &nonce_b, &[], &ct_a, &tag_a).is_err());
}
