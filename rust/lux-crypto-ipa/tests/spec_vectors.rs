// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// IPA spec-vector integration test.
//
// IPA commit asserts byte-equal output for known coefficient inputs. The
// canonical empty-vector commit equals the Banderwagon identity (point at
// infinity) — every IPA implementation (gnark-crypto, go-ipa, ethereum's
// banderwagon-py) returns the same 32-byte canonical encoding for the
// empty input.

use lux_crypto_ipa::{commit, multiproof_verify, Error, COEFF_LEN, COMMIT_LEN, MAX_SRS_LEN, PROOF_LEN};

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
fn empty_input_commit_is_identity() {
    let want: [u8; COMMIT_LEN] = from_hex(IDENTITY_HEX);
    let got = commit(&[]).expect("empty commit");
    assert_eq!(got, want);
}

#[test]
fn single_zero_coefficient_commit_is_identity() {
    let want: [u8; COMMIT_LEN] = from_hex(IDENTITY_HEX);
    let coeffs = [0u8; COEFF_LEN];
    let got = commit(&coeffs).expect("zero coeff commit");
    assert_eq!(got, want);
}

#[test]
fn deterministic_commit_same_input_same_output() {
    let mut coeffs = vec![0u8; 4 * COEFF_LEN];
    for i in 0..4 {
        coeffs[i * COEFF_LEN + 31] = (i + 1) as u8;
    }
    let c1 = commit(&coeffs).unwrap();
    let c2 = commit(&coeffs).unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn distinct_coeffs_change_commit() {
    let mut a = vec![0u8; 4 * COEFF_LEN];
    a[31] = 1;
    let mut b = vec![0u8; 4 * COEFF_LEN];
    b[63] = 1;
    let ca = commit(&a).unwrap();
    let cb = commit(&b).unwrap();
    assert_ne!(ca, cb);
}

#[test]
fn coeff_at_position_zero_only_uses_g0() {
    // Coefficient at position 0 with value 1 must equal commit([1]) == G_0.
    let mut a = vec![0u8; COEFF_LEN];
    a[31] = 1;
    let mut b = vec![0u8; 4 * COEFF_LEN];
    b[31] = 1; // coefficient 0 = 1; coeffs 1..3 = 0
    let ca = commit(&a).unwrap();
    let cb = commit(&b).unwrap();
    // Padding with zero-valued coefficients shifts SRS index but the result
    // is the same point because zero coefficients don't contribute.
    assert_eq!(ca, cb);
}

#[test]
fn over_srs_length_rejected() {
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
    let res = multiproof_verify(&[], &[], &[], &proof);
    assert!(res.is_err());
}

#[test]
fn multiproof_verify_rejects_mismatched_input_lengths() {
    let proof = [0u8; PROOF_LEN];
    // 1 Cs entry but 2 ys entries.
    let cs = vec![0u8; 32];
    let ys = vec![0u8; 64];
    let zs = vec![0u8; 1];
    assert!(multiproof_verify(&cs, &ys, &zs, &proof).is_err());
}

#[test]
fn multiproof_verify_rejects_invalid_proof() {
    let proof = [0xffu8; PROOF_LEN];
    let cs = vec![0u8; 32];
    let ys = vec![0u8; 32];
    let zs = vec![0u8; 1];
    let res = multiproof_verify(&cs, &ys, &zs, &proof);
    assert!(res.is_err());
}

#[test]
fn lengths_match_constants() {
    assert_eq!(COMMIT_LEN, 32);
    assert_eq!(COEFF_LEN, 32);
    assert_eq!(PROOF_LEN, 576);
    assert_eq!(MAX_SRS_LEN, 256);
}
