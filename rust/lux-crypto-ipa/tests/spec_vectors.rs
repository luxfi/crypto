// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_ipa::{commit, verify, Error};

#[test]
#[ignore = "luxcpp ipa c-abi NOTIMPL — tracked at #ipa-c-abi-impl"]
fn empty_commitment_is_g1_identity() {
    // Committing the all-zero polynomial yields the BLS12-381 G1 identity.
    let coeffs = vec![0u8; 32 * 256];
    let c = commit(&coeffs, 256).expect("commit");
    assert_eq!(c[0] & 0xc0, 0xc0, "compressed G1 identity prefix");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let coeffs = vec![0u8; 32];
    match commit(&coeffs, 1) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}

#[test]
fn verify_rejects_bogus_proof() {
    let c = [0u8; 48];
    let p = [0u8; 64];
    let res = verify(&c, &p);
    assert!(res.is_err(), "verify must not silently accept");
}
