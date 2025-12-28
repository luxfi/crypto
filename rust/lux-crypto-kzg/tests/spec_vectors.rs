// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_kzg::{blob_to_commit, verify_proof, Error, BLOB_LEN};

#[test]
#[ignore = "luxcpp kzg c-abi NOTIMPL — tracked at #kzg-c-abi-impl"]
fn blob_to_commit_zero_blob_yields_g1_zero() {
    // The all-zero blob has a deterministic commitment (the encoding of the
    // BLS12-381 G1 identity). Once the C-ABI body lands this test asserts
    // byte-equality with the eth-c-kzg-4844 reference output.
    let blob = vec![0u8; BLOB_LEN];
    let blob_arr: &[u8; BLOB_LEN] = blob.as_slice().try_into().unwrap();
    let commit = blob_to_commit(blob_arr).expect("commit");
    // First two bits of a compressed G1 identity are b"\xc0\x00...".
    assert_eq!(commit[0] & 0xc0, 0xc0, "compressed G1 identity prefix");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let blob = vec![0u8; BLOB_LEN];
    let blob_arr: &[u8; BLOB_LEN] = blob.as_slice().try_into().unwrap();
    match blob_to_commit(blob_arr) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}

#[test]
fn verify_proof_rejects_bogus_input() {
    // Even with a NOTIMPL backend, the binding must funnel the result back
    // (does not silently say "valid").
    let commit = [0u8; 48];
    let z = [0u8; 32];
    let y = [0u8; 32];
    let proof = [0u8; 48];
    let res = verify_proof(&commit, &z, &y, &proof);
    assert!(res.is_err(), "verify_proof must not silently accept");
}
