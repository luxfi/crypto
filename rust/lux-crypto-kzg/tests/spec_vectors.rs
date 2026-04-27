// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// EIP-4844 KZG `verify_proof` (the EVM precompile at 0x0a) integration test.
//
// Note: this build of luxcpp/crypto wires only `kzg_verify_proof`. The
// three EL-side blob ops (`blob_to_commit`, `commit_to_proof`,
// `verify_blob`) live in a separate translation unit (c_kzg_blob.cpp) and
// are not present in `libkzg.a` or `libkzg_cpu.a` for this build, so the
// Rust binding's `blob_to_commit`/`commit_to_proof`/`verify_blob` return
// `Internal(-5)` (NOTIMPL). The crate exposes the API surface for forward
// compatibility — once the c-abi gets the blob TU linked in, no Rust
// changes are needed.
//
// Spec vectors are mirrored from
// `luxcpp/crypto/kzg/test/kzg_test.cpp` which is itself a port of
// `cevm/test/unittests/precompiles_kzg_test.cpp` (Apache-2.0). Mathematical
// content traces to EIP-4844 §3.4.

use lux_crypto_kzg::{
    blob_to_commit, commit_to_proof, verify_blob, verify_proof, Error, BLOB_LEN, COMMIT_LEN,
    PROOF_LEN, SCALAR_LEN,
};

const G1_GENERATOR_X: [u8; 48] = [
    0x17, 0xF1, 0xD3, 0xA7, 0x31, 0x97, 0xD7, 0x94, 0x26, 0x95, 0x63, 0x8C, 0x4F, 0xA9, 0xAC, 0x0F,
    0xC3, 0x68, 0x8C, 0x4F, 0x97, 0x74, 0xB9, 0x05, 0xA1, 0x4E, 0x3A, 0x3F, 0x17, 0x1B, 0xAC, 0x58,
    0x6C, 0x55, 0xE8, 0x3F, 0xF9, 0x7A, 0x1A, 0xEF, 0xFB, 0x3A, 0xF0, 0x0A, 0xDB, 0x22, 0xC6, 0xBB,
];

fn point_at_infinity() -> [u8; COMMIT_LEN] {
    let mut b = [0u8; COMMIT_LEN];
    b[0] = 0xC0; // G1 compressed point-at-infinity flag (compressed + infinity)
    b
}

fn g1_generator_compressed() -> [u8; COMMIT_LEN] {
    let mut c = [0u8; COMMIT_LEN];
    c.copy_from_slice(&G1_GENERATOR_X);
    c[0] |= 0x80; // compressed-form flag
    c
}

#[test]
fn verify_proof_zero_polynomial_accepted() {
    // f(x) = 0; commitment = [0]_1, proof = [0]_1, y = 0.
    let pi = point_at_infinity();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17; // arbitrary non-zero z
    let y = [0u8; SCALAR_LEN];
    verify_proof(&pi, &z, &y, &pi).expect("zero-polynomial verify");
}

#[test]
fn verify_proof_constant_polynomial_accepted() {
    // f(x) = 1; commitment = G1 generator [1]_1, proof = [0]_1, y = 1.
    let c = g1_generator_compressed();
    let pi = point_at_infinity();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17;
    let mut y = [0u8; SCALAR_LEN];
    y[31] = 1;
    verify_proof(&c, &z, &y, &pi).expect("constant-polynomial verify");
}

#[test]
fn verify_proof_rejects_z_at_or_above_bls_modulus() {
    // z is the all-0xFF scalar, which is > BLS Fr modulus.
    let pi = point_at_infinity();
    let z = [0xFFu8; SCALAR_LEN];
    let y = [0u8; SCALAR_LEN];
    assert_eq!(
        verify_proof(&pi, &z, &y, &pi).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn verify_proof_rejects_y_at_or_above_bls_modulus() {
    let pi = point_at_infinity();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17;
    let y = [0xFFu8; SCALAR_LEN];
    assert_eq!(
        verify_proof(&pi, &z, &y, &pi).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn verify_proof_rejects_off_curve_commitment() {
    let mut bad_c = [0u8; COMMIT_LEN];
    bad_c[0] = 0x80; // compressed flag, but x is zero — not on curve
    bad_c[47] = 0x01;
    let z = [0u8; SCALAR_LEN];
    let y = [0u8; SCALAR_LEN];
    let pi = point_at_infinity();
    assert_eq!(
        verify_proof(&bad_c, &z, &y, &pi).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn verify_proof_rejects_wrong_proof_for_constant_polynomial() {
    // f(x) = 1, but submit a non-zero G1 element as proof. Pairing check fails.
    let c = g1_generator_compressed();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17;
    let mut y = [0u8; SCALAR_LEN];
    y[31] = 1;
    // Wrong proof: a copy of the commitment (G1 generator) instead of [0]_1.
    let wrong_proof = c;
    assert_eq!(
        verify_proof(&c, &z, &y, &wrong_proof).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn verify_proof_rejects_y_mismatch_zero_polynomial() {
    // f(x)=0 commitment, but claim y != 0.
    let pi = point_at_infinity();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17;
    let mut y_bad = [0u8; SCALAR_LEN];
    y_bad[31] = 5;
    assert_eq!(
        verify_proof(&pi, &z, &y_bad, &pi).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn verify_proof_rejects_y_mismatch_constant_polynomial() {
    // f(x)=1 commitment, but claim y=2.
    let c = g1_generator_compressed();
    let pi = point_at_infinity();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17;
    let mut y_wrong = [0u8; SCALAR_LEN];
    y_wrong[31] = 2;
    assert_eq!(
        verify_proof(&c, &z, &y_wrong, &pi).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn verify_proof_rejects_zero_versioned_hash_zero_inputs() {
    // The body computes a versioned-hash from the commitment; an all-zero
    // commitment produces a SHA-256 hash that does not have the
    // versioned-hash version byte 0x01, so the body's invariant rejects
    // by short-circuiting.
    let c = [0u8; COMMIT_LEN];
    let z = [0u8; SCALAR_LEN];
    let y = [0u8; SCALAR_LEN];
    let proof = [0u8; PROOF_LEN];
    let res = verify_proof(&c, &z, &y, &proof);
    assert!(res.is_err());
}

#[test]
fn verify_proof_deterministic() {
    let pi = point_at_infinity();
    let mut z = [0u8; SCALAR_LEN];
    z[13] = 17;
    let y = [0u8; SCALAR_LEN];
    let r1 = verify_proof(&pi, &z, &y, &pi);
    let r2 = verify_proof(&pi, &z, &y, &pi);
    assert_eq!(r1, r2);
}

#[test]
fn lengths_match_constants() {
    assert_eq!(BLOB_LEN, 131072);
    assert_eq!(COMMIT_LEN, 48);
    assert_eq!(PROOF_LEN, 48);
    assert_eq!(SCALAR_LEN, 32);
}

#[test]
fn blob_ops_return_notimpl_in_this_build() {
    // The blob ops live in a separate TU (c_kzg_blob.cpp) that is not
    // included in libkzg/libkzg_cpu in this build, so the c-abi shim
    // returns CRYPTO_ERR_NOTIMPL = -5. We verify the Rust binding
    // surfaces this as Internal(-5) so callers know the op is unwired.
    let blob = Box::new([0u8; BLOB_LEN]);
    let z = [0u8; SCALAR_LEN];
    let commit = [0u8; COMMIT_LEN];
    let proof = [0u8; PROOF_LEN];
    assert_eq!(blob_to_commit(&blob).unwrap_err(), Error::Internal(-5));
    assert_eq!(commit_to_proof(&blob, &z).unwrap_err(), Error::Internal(-5));
    assert_eq!(verify_blob(&blob, &commit, &proof).unwrap_err(), Error::Internal(-5));
}
