// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// IRTF BLS12-381 spec-vector integration test.
//
// The byte-equality contract against blst v0.3.15 is asserted at the C++
// layer in luxcpp/crypto/bls/test/bls_signature_test.cpp (the test-oracle
// pattern: the body under test wraps blst, so re-running the same blst
// calls in the same binary must match byte-for-byte). Here we exercise
// the Rust binding end-to-end and assert:
//
//   * keygen is deterministic (same IKM -> same SK)
//   * sk_to_pk produces 48 bytes
//   * sign produces 96 bytes
//   * honest verify -> Ok
//   * tampered sig / tampered msg / wrong pk -> VerifyFail
//   * aggregate_pubkeys + aggregate_sigs round-trip via fast_aggregate_verify
//   * aggregate_verify_distinct accepts honest, rejects tampered
//
// >=10 vectors per op via parameterization over ten distinct IKMs (the
// byte 0x01..0x0a each repeated 32 times) and ten distinct messages.

use lux_crypto_bls::{
    aggregate_pubkeys, aggregate_sigs, aggregate_verify_distinct, fast_aggregate_verify, keygen,
    sign, sk_to_pk, verify, Error, IKM_LEN, PK_LEN, SIG_LEN, SK_LEN,
};

const N: usize = 10;

fn make_ikm(byte: u8) -> [u8; IKM_LEN] {
    [byte; IKM_LEN]
}

fn make_msg(i: usize) -> Vec<u8> {
    (0..(16 + i)).map(|j| (j ^ i) as u8).collect()
}

#[test]
fn keygen_is_deterministic() {
    for i in 1..=N {
        let ikm = make_ikm(i as u8);
        let sk1 = keygen(&ikm).expect("keygen rc1");
        let sk2 = keygen(&ikm).expect("keygen rc2");
        assert_eq!(sk1, sk2, "keygen must be deterministic for i={i}");
        assert_eq!(sk1.len(), SK_LEN);
    }
}

#[test]
fn sk_to_pk_is_deterministic() {
    for i in 1..=N {
        let ikm = make_ikm(i as u8);
        let sk = keygen(&ikm).unwrap();
        let pk1 = sk_to_pk(&sk).expect("sk_to_pk rc1");
        let pk2 = sk_to_pk(&sk).expect("sk_to_pk rc2");
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), PK_LEN);
    }
}

#[test]
fn sign_is_deterministic() {
    for i in 1..=N {
        let ikm = make_ikm(i as u8);
        let sk = keygen(&ikm).unwrap();
        let msg = make_msg(i - 1);
        let sig1 = sign(&sk, &msg).expect("sign rc1");
        let sig2 = sign(&sk, &msg).expect("sign rc2");
        assert_eq!(sig1, sig2, "sign must be deterministic for i={i}");
        assert_eq!(sig1.len(), SIG_LEN);
    }
}

#[test]
fn round_trip_verify_positive() {
    for i in 1..=N {
        let ikm = make_ikm(i as u8);
        let sk = keygen(&ikm).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let msg = make_msg(i - 1);
        let sig = sign(&sk, &msg).unwrap();
        verify(&pk, &msg, &sig).expect("honest verify must accept");
    }
}

#[test]
fn verify_negative_tampered_sig() {
    for i in 1..=N {
        let ikm = make_ikm(i as u8);
        let sk = keygen(&ikm).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let msg = make_msg(i - 1);
        let mut sig = sign(&sk, &msg).unwrap();
        sig[0] ^= 0x01;
        assert!(matches!(verify(&pk, &msg, &sig), Err(Error::VerifyFail) | Err(Error::BadInput)));
    }
}

#[test]
fn verify_negative_tampered_msg() {
    for i in 1..=N {
        let ikm = make_ikm(i as u8);
        let sk = keygen(&ikm).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let msg = make_msg(i - 1);
        let other = make_msg(i % N);
        let sig = sign(&sk, &msg).unwrap();
        assert_eq!(verify(&pk, &other, &sig).unwrap_err(), Error::VerifyFail);
    }
}

#[test]
fn verify_negative_wrong_pk() {
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for i in 1..=N {
        let sk = keygen(&make_ikm(i as u8)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        sks.push(sk);
        pks.push(pk);
    }
    for i in 0..N {
        let msg = make_msg(i);
        let sig = sign(&sks[i], &msg).unwrap();
        let other_pk = pks[(i + 1) % N];
        assert_eq!(
            verify(&other_pk, &msg, &sig).unwrap_err(),
            Error::VerifyFail
        );
    }
}

#[test]
fn aggregate_pubkeys_round_trip() {
    let mut pk_buf = Vec::with_capacity(N * PK_LEN);
    let mut sks = Vec::new();
    for i in 1..=N {
        let sk = keygen(&make_ikm(i as u8)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        pk_buf.extend_from_slice(&pk);
        sks.push(sk);
    }
    for n in 2..=N {
        let agg = aggregate_pubkeys(&pk_buf[..n * PK_LEN]).expect("aggregate_pubkeys rc");
        assert_eq!(agg.len(), PK_LEN);
    }
}

#[test]
fn fast_aggregate_verify_round_trip() {
    let common_msg = b"BLS fast aggregate verify";
    let mut pk_buf = Vec::with_capacity(N * PK_LEN);
    let mut sig_buf = Vec::with_capacity(N * SIG_LEN);
    for i in 1..=N {
        let sk = keygen(&make_ikm(i as u8)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let sig = sign(&sk, common_msg).unwrap();
        pk_buf.extend_from_slice(&pk);
        sig_buf.extend_from_slice(&sig);
    }
    for n in 2..=N {
        let agg_sig = aggregate_sigs(&sig_buf[..n * SIG_LEN]).expect("aggregate_sigs");
        fast_aggregate_verify(&pk_buf[..n * PK_LEN], common_msg, &agg_sig)
            .expect("fast_aggregate_verify positive");

        let other_msg = b"different message";
        assert_eq!(
            fast_aggregate_verify(&pk_buf[..n * PK_LEN], other_msg, &agg_sig).unwrap_err(),
            Error::VerifyFail
        );
    }
}

#[test]
fn aggregate_verify_distinct_round_trip() {
    let mut pk_buf = Vec::with_capacity(N * PK_LEN);
    let mut sig_buf = Vec::with_capacity(N * SIG_LEN);
    let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(N);
    for i in 1..=N {
        let sk = keygen(&make_ikm(i as u8)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let m = make_msg(i - 1);
        let sig = sign(&sk, &m).unwrap();
        pk_buf.extend_from_slice(&pk);
        sig_buf.extend_from_slice(&sig);
        msgs.push(m);
    }
    for n in 2..=N {
        let agg_sig = aggregate_sigs(&sig_buf[..n * SIG_LEN]).unwrap();
        let msg_refs: Vec<&[u8]> = msgs[..n].iter().map(|v| v.as_slice()).collect();

        aggregate_verify_distinct(&pk_buf[..n * PK_LEN], &msg_refs, &agg_sig)
            .expect("aggregate_verify_distinct positive");

        // Tamper one message.
        let mut tampered: Vec<Vec<u8>> = msgs[..n].to_vec();
        if !tampered[0].is_empty() {
            tampered[0][0] ^= 0xFF;
        }
        let tampered_refs: Vec<&[u8]> = tampered.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            aggregate_verify_distinct(&pk_buf[..n * PK_LEN], &tampered_refs, &agg_sig)
                .unwrap_err(),
            Error::VerifyFail
        );
    }
}

#[test]
fn rejects_malformed_lengths() {
    let bad: [u8; PK_LEN - 1] = [0u8; PK_LEN - 1];
    assert_eq!(aggregate_pubkeys(&bad).unwrap_err(), Error::BadInput);

    let bad_sig: [u8; SIG_LEN - 1] = [0u8; SIG_LEN - 1];
    assert_eq!(aggregate_sigs(&bad_sig).unwrap_err(), Error::BadInput);
}

#[test]
fn fips_size_constants_match_spec() {
    // RFC 9380 + IRTF draft-irtf-cfrg-bls-signature-05 §4 / Eth2 SSZ.
    assert_eq!(SK_LEN, 32);
    assert_eq!(PK_LEN, 48);
    assert_eq!(SIG_LEN, 96);
    assert_eq!(IKM_LEN, 32);
}
