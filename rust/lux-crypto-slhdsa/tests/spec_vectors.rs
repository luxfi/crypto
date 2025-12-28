// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// FIPS 205 SLH-DSA spec-vector integration test (fast variants only).
//
// SLH-DSA is computationally expensive (especially SHA2-256f / SHAKE-256f
// keygen + sign), so this test runs only the 128f variants by default. The
// 192f and 256f variants are gated behind `#[ignore]` and can be exercised
// with `cargo test --ignored`.

use lux_crypto_slhdsa::{keygen, sign, verify, Error, Mode};

fn round_trip(mode: Mode) {
    let (pk, sk) = keygen(mode).expect("keygen must succeed");
    assert_eq!(pk.len(), mode.pk_len());
    assert_eq!(sk.len(), mode.sk_len());

    let msg = b"FIPS 205 SLH-DSA round-trip";
    let sig = sign(mode, &sk, msg).expect("sign must succeed");
    assert_eq!(sig.len(), mode.sig_max());

    verify(mode, &pk, msg, &sig).expect("verify must succeed");
}

#[test]
fn round_trip_sha2_128f() {
    round_trip(Mode::Sha2_128F);
}

#[test]
fn round_trip_shake_128f() {
    round_trip(Mode::Shake128F);
}

#[test]
#[ignore = "192f keygen+sign takes >5s"]
fn round_trip_sha2_192f() {
    round_trip(Mode::Sha2_192F);
}

#[test]
#[ignore = "192f keygen+sign takes >5s"]
fn round_trip_shake_192f() {
    round_trip(Mode::Shake192F);
}

#[test]
#[ignore = "256f keygen+sign takes >30s"]
fn round_trip_sha2_256f() {
    round_trip(Mode::Sha2_256F);
}

#[test]
#[ignore = "256f keygen+sign takes >30s"]
fn round_trip_shake_256f() {
    round_trip(Mode::Shake256F);
}

#[test]
fn tampered_signature_fails_sha2_128f() {
    let (pk, sk) = keygen(Mode::Sha2_128F).unwrap();
    let msg = b"slhdsa tamper";
    let mut sig = sign(Mode::Sha2_128F, &sk, msg).unwrap();
    sig[0] ^= 0x01;
    assert_eq!(
        verify(Mode::Sha2_128F, &pk, msg, &sig).unwrap_err(),
        Error::VerifyFail,
    );
}

#[test]
fn tampered_message_fails_shake_128f() {
    let (pk, sk) = keygen(Mode::Shake128F).unwrap();
    let msg = b"original";
    let other = b"different";
    let sig = sign(Mode::Shake128F, &sk, msg).unwrap();
    assert_eq!(
        verify(Mode::Shake128F, &pk, other, &sig).unwrap_err(),
        Error::VerifyFail,
    );
}

#[test]
fn cross_keypair_isolation_sha2_128f() {
    let (pk_a, sk_a) = keygen(Mode::Sha2_128F).unwrap();
    let (pk_b, _sk_b) = keygen(Mode::Sha2_128F).unwrap();
    let msg = b"cross check";
    let sig = sign(Mode::Sha2_128F, &sk_a, msg).unwrap();
    assert_eq!(
        verify(Mode::Sha2_128F, &pk_b, msg, &sig).unwrap_err(),
        Error::VerifyFail,
    );
    drop(pk_a);
}

#[test]
fn fips205_size_constants_match_spec() {
    // FIPS 205 §10 "Parameter Sets", Table 2 (fast variants).
    let modes = [
        (Mode::Sha2_128F, 32, 64, 17088),
        (Mode::Sha2_192F, 48, 96, 35664),
        (Mode::Sha2_256F, 64, 128, 49856),
        (Mode::Shake128F, 32, 64, 17088),
        (Mode::Shake192F, 48, 96, 35664),
        (Mode::Shake256F, 64, 128, 49856),
    ];
    for (m, pk, sk, sig) in modes {
        assert_eq!(m.pk_len(), pk, "{m:?} pk");
        assert_eq!(m.sk_len(), sk, "{m:?} sk");
        assert_eq!(m.sig_max(), sig, "{m:?} sig");
    }
}

#[test]
fn malformed_pk_rejected_in_verify() {
    let (pk, sk) = keygen(Mode::Sha2_128F).unwrap();
    let msg = b"x";
    let sig = sign(Mode::Sha2_128F, &sk, msg).unwrap();
    let bad_pk = &pk[..pk.len() - 1];
    assert_eq!(
        verify(Mode::Sha2_128F, bad_pk, msg, &sig).unwrap_err(),
        Error::BadInput,
    );
}

#[test]
fn empty_message_round_trip() {
    let (pk, sk) = keygen(Mode::Shake128F).unwrap();
    let msg: &[u8] = &[];
    let sig = sign(Mode::Shake128F, &sk, msg).unwrap();
    verify(Mode::Shake128F, &pk, msg, &sig).unwrap();
}

#[test]
fn long_message_round_trip() {
    let (pk, sk) = keygen(Mode::Sha2_128F).unwrap();
    let msg = vec![0xAAu8; 4096];
    let sig = sign(Mode::Sha2_128F, &sk, &msg).unwrap();
    verify(Mode::Sha2_128F, &pk, &msg, &sig).unwrap();
}
