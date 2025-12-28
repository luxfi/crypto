// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_bls::{keygen, sign, sk_to_pk, verify, Error};

#[test]
#[ignore = "luxcpp bls c-abi NOTIMPL — tracked at #bls-c-abi-impl"]
fn keygen_sign_verify_roundtrip() {
    let seed = [0x42_u8; 32];
    let sk = keygen(&seed).expect("keygen");
    let pk = sk_to_pk(&sk).expect("sk_to_pk");
    let msg = b"BLS roundtrip";
    let sig = sign(&sk, msg).expect("sign");
    verify(&pk, msg, &sig).expect("verify");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let seed = [0u8; 32];
    match keygen(&seed) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
        Err(other) => panic!("unexpected error: {:?}", other),
    }
}
