// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Round-trip integration tests for SLH-DSA across all six FIPS 205 'f' (fast)
// parameter sets. Byte-equal NIST KAT vector tests live in the C++ side
// (build-cto/slhdsa_kat_test, 498 PASS lines). These tests verify the Rust
// binding's invariants against the underlying byte-equal CPU body:
//
//   1. keygen(mode, pk, sk)         -> CRYPTO_OK
//   2. sign(mode, sk, msg, sig)     -> sig_len == mode.sig_len()
//   3. verify(mode, pk, msg, sig)   -> Ok(())
//   4. verify with mutated sig      -> Err(InvalidSignature)
//   5. verify with mutated pk       -> Err(InvalidSignature)
//   6. verify with mutated msg      -> Err(InvalidSignature)
//   7. wrong-length pk              -> Err(InvalidLength)
//
// 256f sign() can take >30s on M1 -- gated behind --include-ignored.

use lux_crypto_slhdsa::{keygen, sign, verify, Error, Mode};

fn roundtrip(mode: Mode, msg: &[u8]) {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    keygen(mode, &mut pk, &mut sk).expect("keygen");

    let mut sig = vec![0u8; mode.sig_len()];
    let n = sign(mode, &sk, msg, &mut sig).expect("sign");
    assert_eq!(n, mode.sig_len(), "{:?}: sig_len mismatch", mode);

    verify(mode, &pk, msg, &sig[..n]).expect("verify(honest)");

    // Tamper signature.
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0x01;
    assert_eq!(
        verify(mode, &pk, msg, &bad_sig[..n]),
        Err(Error::InvalidSignature),
        "{:?}: tampered sig should reject",
        mode
    );

    // Tamper public key.
    let mut bad_pk = pk.clone();
    bad_pk[0] ^= 0x01;
    assert_eq!(
        verify(mode, &bad_pk, msg, &sig[..n]),
        Err(Error::InvalidSignature),
        "{:?}: tampered pk should reject",
        mode
    );

    // Tamper message (only when non-empty).
    if !msg.is_empty() {
        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 0x01;
        assert_eq!(
            verify(mode, &pk, &bad_msg, &sig[..n]),
            Err(Error::InvalidSignature),
            "{:?}: tampered msg should reject",
            mode
        );
    }

    // Wrong-length public key.
    let short_pk = &pk[..pk.len() - 1];
    assert_eq!(
        verify(mode, short_pk, msg, &sig[..n]),
        Err(Error::InvalidLength),
        "{:?}: short pk should be rejected as InvalidLength",
        mode
    );
}

#[test]
fn sha2_128f_roundtrip() {
    roundtrip(Mode::Sha2_128f, b"lux SLH-DSA-SHA2-128f roundtrip");
}

#[test]
fn shake_128f_roundtrip() {
    roundtrip(Mode::Shake_128f, b"lux SLH-DSA-SHAKE-128f roundtrip");
}

#[test]
fn sha2_192f_roundtrip() {
    roundtrip(Mode::Sha2_192f, b"lux SLH-DSA-SHA2-192f roundtrip");
}

#[test]
fn shake_192f_roundtrip() {
    roundtrip(Mode::Shake_192f, b"lux SLH-DSA-SHAKE-192f roundtrip");
}

// 256f sign() takes ~30-60s on M1; ignored by default.
#[test]
#[ignore]
fn sha2_256f_roundtrip() {
    roundtrip(Mode::Sha2_256f, b"lux SLH-DSA-SHA2-256f roundtrip");
}

#[test]
#[ignore]
fn shake_256f_roundtrip() {
    roundtrip(Mode::Shake_256f, b"lux SLH-DSA-SHAKE-256f roundtrip");
}

#[test]
fn empty_message_sha2_128f() {
    roundtrip(Mode::Sha2_128f, b"");
}

#[test]
fn mode_sizes_match_fips205() {
    // NIST FIPS 205 §10 parameter catalogue.
    assert_eq!(Mode::Sha2_128f.pk_len(), 32);
    assert_eq!(Mode::Sha2_128f.sk_len(), 64);
    assert_eq!(Mode::Sha2_128f.sig_len(), 17088);

    assert_eq!(Mode::Sha2_192f.pk_len(), 48);
    assert_eq!(Mode::Sha2_192f.sk_len(), 96);
    assert_eq!(Mode::Sha2_192f.sig_len(), 35664);

    assert_eq!(Mode::Sha2_256f.pk_len(), 64);
    assert_eq!(Mode::Sha2_256f.sk_len(), 128);
    assert_eq!(Mode::Sha2_256f.sig_len(), 49856);

    // SHAKE shares sizes with SHA2 at each security level.
    assert_eq!(Mode::Shake_128f.pk_len(), Mode::Sha2_128f.pk_len());
    assert_eq!(Mode::Shake_192f.pk_len(), Mode::Sha2_192f.pk_len());
    assert_eq!(Mode::Shake_256f.pk_len(), Mode::Sha2_256f.pk_len());
}
