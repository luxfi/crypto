// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// ChaCha20-Poly1305 AEAD binding smoke test. Either the full RFC 8439
// surface is wired (seal/open round-trip) or both entry points return
// CRYPTO_ERR_NOTIMPL (-5) consistently.

use lux_crypto_aead::{open, seal, Error, KEY_LEN, NONCE_LEN, TAG_LEN};

#[test]
fn seal_open_roundtrip_or_notimpl() {
    let key = [0x11u8; KEY_LEN];
    let nonce = [0x22u8; NONCE_LEN];
    let aad = b"lux-aead-binding-aad";
    let pt = b"lux-aead-binding-plaintext";
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; TAG_LEN];

    match seal(&key, &nonce, aad, pt, &mut ct, &mut tag) {
        Ok(()) => {
            let mut decrypted = vec![0u8; ct.len()];
            open(&key, &nonce, aad, &ct, &tag, &mut decrypted)
                .expect("open must accept honest seal output");
            assert_eq!(&decrypted[..], &pt[..]);
        }
        Err(Error::InternalError(-5)) => {
            // CRYPTO_ERR_NOTIMPL; open must agree.
            let mut decrypted = vec![0u8; ct.len()];
            assert!(matches!(
                open(&key, &nonce, aad, &ct, &tag, &mut decrypted),
                Err(Error::InternalError(-5))
            ));
        }
        Err(other) => panic!("unexpected seal error: {:?}", other),
    }
}
