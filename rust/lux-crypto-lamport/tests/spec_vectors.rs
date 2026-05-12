// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_lamport::{keygen, sign, verify, PK_LEN, SIG_LEN, SK_LEN};

#[test]
fn keygen_sign_verify_roundtrip() {
    // Canonical Lamport-OTS round-trip against the luxcpp body
    // (luxcpp/crypto/lamport/cpp/lamport.cpp). Parameter sizes are exported by
    // the binding as PK_LEN / SK_LEN / SIG_LEN.
    let seed = [0u8; 32];
    let mut pk = vec![0u8; PK_LEN];
    let mut sk = vec![0u8; SK_LEN];
    keygen(&seed, &mut pk, &mut sk).expect("keygen");
    let msg = [0xAA_u8; 32];
    let mut sig = vec![0u8; SIG_LEN];
    sign(&sk, &msg, &mut sig).expect("sign");
    verify(&pk, &msg, &sig).expect("verify");
}

#[test]
fn verify_rejects_tampered_signature() {
    let seed = [0x11u8; 32];
    let mut pk = vec![0u8; PK_LEN];
    let mut sk = vec![0u8; SK_LEN];
    keygen(&seed, &mut pk, &mut sk).expect("keygen");
    let msg = [0x55_u8; 32];
    let mut sig = vec![0u8; SIG_LEN];
    sign(&sk, &msg, &mut sig).expect("sign");
    // Flip a byte in the signature; verify must reject.
    sig[0] ^= 0x01;
    assert!(verify(&pk, &msg, &sig).is_err());
}
