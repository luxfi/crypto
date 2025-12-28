// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_aead::{open, seal, Error, KEY_LEN, NONCE_LEN, TAG_LEN};

#[test]
#[ignore = "luxcpp aead c-abi NOTIMPL — tracked at #aead-c-abi-impl"]
fn rfc8439_a_5_seal_then_open() {
    // RFC 8439 §A.5: ChaCha20-Poly1305 AEAD known-answer vector.
    let key: [u8; KEY_LEN] = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86,
        0x04, 0xf6, 0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ];
    let nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
    let pt = b"sample plaintext";
    let aad = b"sample aad";
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; TAG_LEN];
    seal(&key, &nonce, aad, pt, &mut ct, &mut tag).expect("seal");
    let mut pt2 = vec![0u8; ct.len()];
    open(&key, &nonce, aad, &ct, &tag, &mut pt2).expect("open");
    assert_eq!(pt2, pt);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let key = [0u8; KEY_LEN];
    let nonce = [0u8; NONCE_LEN];
    let pt = [0u8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; TAG_LEN];
    match seal(&key, &nonce, b"", &pt, &mut ct, &mut tag) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
