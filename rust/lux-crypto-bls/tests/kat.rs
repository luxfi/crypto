// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// BLS12-381 binding smoke test. The canonical luxcpp body currently returns
// CRYPTO_ERR_NOTIMPL (-5) until the blst integration is wired. This test
// asserts the C-ABI is reachable through Rust and reports a coherent status.

use lux_crypto_bls::{keygen, sk_to_pk, sign, verify, Error, PK_LEN, SEED_LEN, SIG_LEN, SK_LEN};

#[test]
fn keygen_sign_verify_roundtrip_or_notimpl() {
    let seed = [0x11u8; SEED_LEN];
    let mut sk = [0u8; SK_LEN];

    match keygen(&seed, &mut sk) {
        Ok(()) => {
            let mut pk = [0u8; PK_LEN];
            sk_to_pk(&sk, &mut pk).expect("sk_to_pk after successful keygen");
            let mut sig = [0u8; SIG_LEN];
            sign(&sk, b"lux-bls-binding-kat", &mut sig).expect("sign after keygen");
            verify(&pk, b"lux-bls-binding-kat", &sig).expect("verify accepts honest sig");
        }
        Err(Error::Internal(-5)) => {
            // CRYPTO_ERR_NOTIMPL: BLS C-ABI surface published, body in flight.
            let mut pk = [0u8; PK_LEN];
            assert!(matches!(sk_to_pk(&sk, &mut pk), Err(Error::Internal(-5))));
        }
        Err(other) => panic!("unexpected keygen error: {:?}", other),
    }
}
