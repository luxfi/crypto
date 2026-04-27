// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// FIPS 203 ML-KEM spec-vector integration test.
//
// The C-ABI body is the vendored PQClean reference. Byte-equal NIST KAT is
// asserted at the C++ layer in `mlkem/test/mlkem_kat_test.cpp`. Here we
// assert the round-trip and parameter-set invariants of the Rust binding.

use lux_crypto_mlkem::{decap, encap, keygen, Error, Mode, SHARED_SECRET_LEN};

const ALL_MODES: [Mode; 3] = [Mode::M512, Mode::M768, Mode::M1024];

fn round_trip(mode: Mode) {
    let (pk, sk) = keygen(mode).expect("keygen must succeed");
    assert_eq!(pk.len(), mode.pk_len());
    assert_eq!(sk.len(), mode.sk_len());

    let (ct, ss_a) = encap(mode, &pk).expect("encap must succeed");
    assert_eq!(ct.len(), mode.ct_len());

    let ss_b = decap(mode, &sk, &ct).expect("decap must succeed");
    assert_eq!(ss_a, ss_b);
}

#[test]
fn round_trip_512() {
    round_trip(Mode::M512);
}

#[test]
fn round_trip_768() {
    round_trip(Mode::M768);
}

#[test]
fn round_trip_1024() {
    round_trip(Mode::M1024);
}

fn implicit_rejection_on_modified_ct(mode: Mode) {
    // FIPS 203 implements implicit rejection: a tampered ciphertext does
    // not return an error. Instead, the decapsulator returns a
    // pseudo-random shared secret derived from sk and ct. The shared
    // secret therefore differs from the encapsulator's, but no error is
    // raised.
    let (pk, sk) = keygen(mode).unwrap();
    let (mut ct, ss_a) = encap(mode, &pk).unwrap();
    ct[0] ^= 0x01;
    let ss_b = decap(mode, &sk, &ct).expect("FIPS 203 implicit rejection");
    assert_ne!(ss_a, ss_b);
}

#[test]
fn implicit_rejection_512() {
    implicit_rejection_on_modified_ct(Mode::M512);
}

#[test]
fn implicit_rejection_768() {
    implicit_rejection_on_modified_ct(Mode::M768);
}

#[test]
fn implicit_rejection_1024() {
    implicit_rejection_on_modified_ct(Mode::M1024);
}

fn cross_keypair_isolation(mode: Mode) {
    let (pk_a, _sk_a) = keygen(mode).unwrap();
    let (_pk_b, sk_b) = keygen(mode).unwrap();
    let (ct, ss_a) = encap(mode, &pk_a).unwrap();
    // FIPS 203 implicit rejection: decap with the wrong sk does not error,
    // but the recovered shared secret is unrelated to ss_a.
    let ss_b = decap(mode, &sk_b, &ct).unwrap();
    assert_ne!(ss_a, ss_b);
}

#[test]
fn cross_keypair_isolation_512() {
    cross_keypair_isolation(Mode::M512);
}

#[test]
fn cross_keypair_isolation_768() {
    cross_keypair_isolation(Mode::M768);
}

#[test]
fn cross_keypair_isolation_1024() {
    cross_keypair_isolation(Mode::M1024);
}

#[test]
fn fips203_size_constants_match_spec() {
    // FIPS 203 §7 "Parameter Sets", Table 2.
    for &m in ALL_MODES.iter() {
        match m {
            Mode::M512 => {
                assert_eq!(m.pk_len(), 800);
                assert_eq!(m.sk_len(), 1632);
                assert_eq!(m.ct_len(), 768);
            }
            Mode::M768 => {
                assert_eq!(m.pk_len(), 1184);
                assert_eq!(m.sk_len(), 2400);
                assert_eq!(m.ct_len(), 1088);
            }
            Mode::M1024 => {
                assert_eq!(m.pk_len(), 1568);
                assert_eq!(m.sk_len(), 3168);
                assert_eq!(m.ct_len(), 1568);
            }
        }
    }
    assert_eq!(SHARED_SECRET_LEN, 32);
}

#[test]
fn malformed_pk_rejected() {
    let (pk, _sk) = keygen(Mode::M768).unwrap();
    // Truncate the pk; encap must reject.
    let bad = &pk[..pk.len() - 1];
    assert_eq!(encap(Mode::M768, bad).unwrap_err(), Error::BadInput);
}

#[test]
fn malformed_ct_rejected() {
    let (_pk, sk) = keygen(Mode::M768).unwrap();
    let bad_ct = vec![0u8; Mode::M768.ct_len() - 1];
    assert_eq!(decap(Mode::M768, &sk, &bad_ct).unwrap_err(), Error::BadInput);
}
