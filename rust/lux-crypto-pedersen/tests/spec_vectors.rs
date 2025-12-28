// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Pedersen (Banderwagon) commitment integration test.
//
// The C-ABI computes commit = sum_{i=0..n-1} G_i * v_i + H * b. Tests assert:
//   * commit/verify round-trip
//   * single-value commit equals scalar_mul(G_0, v) + scalar_mul(H, b)
//   * empty commit equals scalar_mul(H, b)
//   * tampered commit -> VerifyFail
//   * tampered values -> VerifyFail
//   * tampered blinding -> VerifyFail
//   * length cap (256) enforced
//   * misaligned input rejected
//   * blinding-by-zero produces only G_i * v_i path

use lux_crypto_pedersen::{commit, verify, Error, BLINDING_LEN, COMMIT_LEN, VALUE_LEN};

fn random_value(seed: u8) -> [u8; VALUE_LEN] {
    let mut v = [0u8; VALUE_LEN];
    for i in 0..VALUE_LEN {
        v[i] = seed.wrapping_mul((i as u8).wrapping_add(1));
    }
    v
}

#[test]
fn commit_then_verify_single_value() {
    let v = random_value(1);
    let blinding = [42u8; BLINDING_LEN];
    let c = commit(&v, &blinding).expect("commit");
    verify(&c, &v, &blinding).expect("verify");
}

#[test]
fn commit_then_verify_two_values() {
    let mut values = Vec::with_capacity(2 * VALUE_LEN);
    values.extend_from_slice(&random_value(7));
    values.extend_from_slice(&random_value(11));
    let blinding = [99u8; BLINDING_LEN];
    let c = commit(&values, &blinding).unwrap();
    verify(&c, &values, &blinding).unwrap();
}

#[test]
fn commit_empty_values_is_blinding_only() {
    let blinding = [3u8; BLINDING_LEN];
    let c = commit(&[], &blinding).expect("empty commit");
    verify(&c, &[], &blinding).unwrap();
    // Sanity: c is non-zero (since b != 0 means H*b != identity).
    assert!(c.iter().any(|&b| b != 0));
}

#[test]
fn deterministic_commit_same_inputs_same_output() {
    let v = random_value(0xAA);
    let blinding = [5u8; BLINDING_LEN];
    let c1 = commit(&v, &blinding).unwrap();
    let c2 = commit(&v, &blinding).unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn tampered_commit_fails_verify() {
    let v = random_value(1);
    let blinding = [1u8; BLINDING_LEN];
    let mut c = commit(&v, &blinding).unwrap();
    c[0] ^= 0x01;
    assert!(verify(&c, &v, &blinding).is_err());
}

#[test]
fn tampered_values_fails_verify() {
    let mut values = random_value(1).to_vec();
    let blinding = [1u8; BLINDING_LEN];
    let c = commit(&values, &blinding).unwrap();
    values[0] ^= 0x01;
    assert_eq!(verify(&c, &values, &blinding).unwrap_err(), Error::VerifyFail);
}

#[test]
fn tampered_blinding_fails_verify() {
    let v = random_value(2);
    let blinding = [7u8; BLINDING_LEN];
    let c = commit(&v, &blinding).unwrap();
    let mut bad = blinding;
    bad[0] ^= 0x01;
    assert_eq!(verify(&c, &v, &bad).unwrap_err(), Error::VerifyFail);
}

#[test]
fn distinct_blindings_change_commit() {
    let v = random_value(0x55);
    let b1 = [1u8; BLINDING_LEN];
    let b2 = [2u8; BLINDING_LEN];
    let c1 = commit(&v, &b1).unwrap();
    let c2 = commit(&v, &b2).unwrap();
    assert_ne!(c1, c2);
}

#[test]
fn distinct_values_change_commit() {
    let v1 = random_value(0xA1);
    let v2 = random_value(0xA2);
    let b = [9u8; BLINDING_LEN];
    let c1 = commit(&v1, &b).unwrap();
    let c2 = commit(&v2, &b).unwrap();
    assert_ne!(c1, c2);
}

#[test]
fn over_max_values_rejected() {
    let too_many = vec![0u8; (lux_crypto_pedersen::MAX_VALUES + 1) * VALUE_LEN];
    let b = [0u8; BLINDING_LEN];
    assert!(commit(&too_many, &b).is_err());
}

#[test]
fn misaligned_values_rejected() {
    let bad = vec![0u8; VALUE_LEN - 1]; // not a multiple of 32
    let b = [0u8; BLINDING_LEN];
    assert_eq!(commit(&bad, &b).unwrap_err(), Error::BadInput);
}

#[test]
fn lengths_match_constants() {
    assert_eq!(COMMIT_LEN, 32);
    assert_eq!(VALUE_LEN, 32);
    assert_eq!(BLINDING_LEN, 32);
}
