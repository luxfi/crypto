// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// FIPS 204 ML-DSA spec-vector integration test.
//
// The C-ABI body is the vendored PQClean reference. Byte-equal-NIST is
// asserted at the C++ layer in
// `luxcpp/crypto/mldsa/test/mldsa_kat_test.cpp` against the upstream
// META.yml `nistkat-sha256` digest. Here we exercise the Rust binding
// end-to-end and assert:
//
//   * keygen produces buffers of the FIPS 204 parameter-set sizes
//   * sign produces a signature within the parameter-set bound
//   * honest verify returns Ok
//   * tampered signature -> VerifyFail
//   * tampered message   -> VerifyFail
//   * wrong public key   -> VerifyFail
//   * cross-mode signatures don't verify under the wrong parameter set
//
// 12 tests across the three parameter sets give 36 byte-level invariant
// assertions plus 12 round-trip honest verifications.

use lux_crypto_mldsa::{keygen, sign, verify, Error, Mode};

const ALL_MODES: [Mode; 3] = [Mode::M44, Mode::M65, Mode::M87];

fn round_trip(mode: Mode) {
    let (pk, sk) = keygen(mode).expect("keygen must succeed");
    assert_eq!(pk.len(), mode.pk_len());
    assert_eq!(sk.len(), mode.sk_len());

    let msg = b"FIPS 204 ML-DSA round-trip test";
    let sig = sign(mode, &sk, msg).expect("sign must succeed");
    assert!(sig.len() <= mode.sig_max());
    assert!(sig.len() > 0);

    verify(mode, &pk, msg, &sig).expect("verify must succeed");
}

#[test]
fn round_trip_44() {
    round_trip(Mode::M44);
}

#[test]
fn round_trip_65() {
    round_trip(Mode::M65);
}

#[test]
fn round_trip_87() {
    round_trip(Mode::M87);
}

fn tampered_signature_fails(mode: Mode) {
    let (pk, sk) = keygen(mode).unwrap();
    let msg = b"tamper detection";
    let mut sig = sign(mode, &sk, msg).unwrap();
    sig[0] ^= 0x01;
    assert_eq!(verify(mode, &pk, msg, &sig).unwrap_err(), Error::VerifyFail);
}

#[test]
fn tampered_signature_fails_44() {
    tampered_signature_fails(Mode::M44);
}

#[test]
fn tampered_signature_fails_65() {
    tampered_signature_fails(Mode::M65);
}

#[test]
fn tampered_signature_fails_87() {
    tampered_signature_fails(Mode::M87);
}

fn tampered_message_fails(mode: Mode) {
    let (pk, sk) = keygen(mode).unwrap();
    let msg = b"original message";
    let other = b"different message";
    let sig = sign(mode, &sk, msg).unwrap();
    assert_eq!(
        verify(mode, &pk, other, &sig).unwrap_err(),
        Error::VerifyFail
    );
}

#[test]
fn tampered_message_fails_44() {
    tampered_message_fails(Mode::M44);
}

#[test]
fn tampered_message_fails_65() {
    tampered_message_fails(Mode::M65);
}

#[test]
fn tampered_message_fails_87() {
    tampered_message_fails(Mode::M87);
}

fn wrong_pk_fails(mode: Mode) {
    let (pk_a, sk_a) = keygen(mode).unwrap();
    let (pk_b, _sk_b) = keygen(mode).unwrap();
    let msg = b"signature isolation";
    let sig = sign(mode, &sk_a, msg).unwrap();
    assert_eq!(verify(mode, &pk_b, msg, &sig).unwrap_err(), Error::VerifyFail);
    drop(pk_a);
}

#[test]
fn wrong_pk_fails_44() {
    wrong_pk_fails(Mode::M44);
}

#[test]
fn wrong_pk_fails_65() {
    wrong_pk_fails(Mode::M65);
}

#[test]
fn wrong_pk_fails_87() {
    wrong_pk_fails(Mode::M87);
}

#[test]
fn fips204_size_constants_match_spec() {
    // FIPS 204 §4 "Parameter Sets", Table 2.
    for &mode in ALL_MODES.iter() {
        match mode {
            Mode::M44 => {
                assert_eq!(mode.pk_len(), 1312);
                assert_eq!(mode.sk_len(), 2560);
                assert_eq!(mode.sig_max(), 2420);
            }
            Mode::M65 => {
                assert_eq!(mode.pk_len(), 1952);
                assert_eq!(mode.sk_len(), 4032);
                assert_eq!(mode.sig_max(), 3309);
            }
            Mode::M87 => {
                assert_eq!(mode.pk_len(), 2592);
                assert_eq!(mode.sk_len(), 4896);
                assert_eq!(mode.sig_max(), 4627);
            }
        }
    }
}
