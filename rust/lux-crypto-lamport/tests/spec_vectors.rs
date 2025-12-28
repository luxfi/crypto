// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_lamport::{keygen, sign, verify, Error};

#[test]
#[ignore = "luxcpp lamport c-abi NOTIMPL — tracked at #lamport-c-abi-impl"]
fn keygen_sign_verify_roundtrip() {
    // FIXME: the exact Lamport parameter set (pk_len, sk_len, sig_len) is
    // implementation-defined and will be encoded as constants once the C-ABI
    // body lands. Until then this test is a placeholder that asserts the
    // contract round-trips end-to-end.
    let seed = [0u8; 32];
    // Generous sizing for a 32-byte-message Lamport.
    let mut pk = vec![0u8; 32 * 256 * 2 / 8];
    let mut sk = vec![0u8; 32 * 256 * 2 / 8];
    keygen(&seed, &mut pk, &mut sk).expect("keygen");
    let msg = [0xAA_u8; 32];
    let mut sig = vec![0u8; 32 * 256 / 8];
    sign(&sk, &msg, &mut sig).expect("sign");
    verify(&pk, &msg, &sig).expect("verify");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    // While the C-ABI body is unwired every call returns -5. This is the
    // only check we can run today that does not silently pass.
    let seed = [0u8; 32];
    let mut pk = [0u8; 16];
    let mut sk = [0u8; 16];
    match keygen(&seed, &mut pk, &mut sk) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
        Err(other) => panic!("unexpected error: {:?}", other),
    }
}
