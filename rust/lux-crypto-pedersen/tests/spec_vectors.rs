// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_pedersen::{commit, verify, Error, BLINDING_LEN};

#[test]
#[ignore = "luxcpp pedersen c-abi NOTIMPL — tracked at #pedersen-c-abi-impl"]
fn commit_then_verify_roundtrip() {
    let values = vec![0xAA_u8; 32 * 4];
    let blinding = [0x42_u8; BLINDING_LEN];
    let c = commit(&values, 4, &blinding).expect("commit");
    verify(&c, &values, 4, &blinding).expect("verify");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let values = [0u8; 32];
    let blinding = [0u8; BLINDING_LEN];
    match commit(&values, 1, &blinding) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
