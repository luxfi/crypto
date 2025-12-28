// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// FIXME: luxcpp/crypto/ed25519/c-abi/c_ed25519.cpp returns CRYPTO_ERR_NOTIMPL.
// Tracked at #ed25519-c-abi-impl. RFC 8032 §7.1 vector tests will land here
// when the C-ABI body lands.

use lux_crypto_ed25519::{keygen, sign, verify, Error, SEED_LEN};

#[test]
#[ignore = "luxcpp ed25519 c-abi NOTIMPL — tracked at #ed25519-c-abi-impl"]
fn rfc8032_test_1_empty_message() {
    let seed: [u8; SEED_LEN] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
        0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let want_pk: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
        0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];
    let (sk, pk) = keygen(&seed).expect("keygen");
    assert_eq!(pk, want_pk);
    let sig = sign(&sk, b"").expect("sign");
    verify(&pk, b"", &sig).expect("verify");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let seed = [0u8; SEED_LEN];
    match keygen(&seed) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
