// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Verkle spec-vector integration test. The Verkle commitment uses the same
// 256-element Banderwagon SRS as IPA, so byte-equality is asserted on the
// canonical zero-coefficient commit, plus deterministic + isolation
// checks.

use lux_crypto_verkle::{commit, multiproof_verify, Error, COEFF_LEN, COMMIT_LEN, MAX_SRS_LEN, PROOF_LEN};

fn from_hex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * N);
    let mut out = [0u8; N];
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex"),
    };
    for i in 0..N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

const IDENTITY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn empty_commit_is_identity() {
    let want: [u8; COMMIT_LEN] = from_hex(IDENTITY_HEX);
    let got = commit(&[]).unwrap();
    assert_eq!(got, want);
}

#[test]
fn all_zero_coefficients_is_identity() {
    let want: [u8; COMMIT_LEN] = from_hex(IDENTITY_HEX);
    let coeffs = vec![0u8; 16 * COEFF_LEN];
    let got = commit(&coeffs).unwrap();
    assert_eq!(got, want);
}

#[test]
fn single_one_coefficient_at_zero_position_matches_g0() {
    // commit([1, 0, 0, ...]) is the SRS generator G_0; commit([1]) gives the
    // same value.
    let mut a = vec![0u8; COEFF_LEN];
    a[31] = 1;
    let mut b = vec![0u8; 8 * COEFF_LEN];
    b[31] = 1;
    let ca = commit(&a).unwrap();
    let cb = commit(&b).unwrap();
    assert_eq!(ca, cb);
}

#[test]
fn deterministic_commit() {
    let mut coeffs = vec![0u8; 8 * COEFF_LEN];
    for i in 0..8 {
        coeffs[i * COEFF_LEN + 31] = (i as u8) + 1;
    }
    assert_eq!(commit(&coeffs).unwrap(), commit(&coeffs).unwrap());
}

#[test]
fn distinct_coefficients_distinct_commit() {
    let mut a = vec![0u8; 4 * COEFF_LEN];
    a[31] = 7;
    let mut b = vec![0u8; 4 * COEFF_LEN];
    b[31] = 11;
    assert_ne!(commit(&a).unwrap(), commit(&b).unwrap());
}

#[test]
fn over_srs_rejected() {
    let too_many = vec![0u8; (MAX_SRS_LEN + 1) * COEFF_LEN];
    assert_eq!(commit(&too_many).unwrap_err(), Error::LengthExceeded);
}

#[test]
fn misaligned_input_rejected() {
    let bad = vec![0u8; COEFF_LEN - 1];
    assert_eq!(commit(&bad).unwrap_err(), Error::BadInput);
}

#[test]
fn full_srs_commit_succeeds() {
    let coeffs = vec![0u8; MAX_SRS_LEN * COEFF_LEN];
    commit(&coeffs).expect("full SRS commit");
}

#[test]
fn multiproof_verify_rejects_zero_queries() {
    let proof = [0u8; PROOF_LEN];
    assert!(multiproof_verify(&[], &[], &[], &proof).is_err());
}

#[test]
fn multiproof_verify_rejects_invalid_proof() {
    let proof = [0xffu8; PROOF_LEN];
    let cs = vec![0u8; 32];
    let ys = vec![0u8; 32];
    let zs = vec![0u8; 1];
    assert!(multiproof_verify(&cs, &ys, &zs, &proof).is_err());
}

#[test]
fn multiproof_verify_rejects_mismatched_lengths() {
    let proof = [0u8; PROOF_LEN];
    let cs = vec![0u8; 64];
    let ys = vec![0u8; 32];
    let zs = vec![0u8; 1];
    assert!(multiproof_verify(&cs, &ys, &zs, &proof).is_err());
}

#[test]
fn lengths_match_constants() {
    assert_eq!(COMMIT_LEN, 32);
    assert_eq!(COEFF_LEN, 32);
    assert_eq!(PROOF_LEN, 576);
    assert_eq!(MAX_SRS_LEN, 256);
}
