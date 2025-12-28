// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_slhdsa::{keygen, sign, verify, Error, Mode};

fn roundtrip(mode: Mode) {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    let seed = [0xA5_u8; 32];
    keygen(mode, &seed, &mut pk, &mut sk).expect("keygen");
    let mut sig = vec![0u8; mode.sig_len()];
    let n = sign(mode, &sk, b"SLH-DSA roundtrip", &mut sig).expect("sign");
    verify(mode, &pk, b"SLH-DSA roundtrip", &sig[..n]).expect("verify");
}

#[test]
#[ignore = "luxcpp slhdsa c-abi NOTIMPL — tracked at #slhdsa-c-abi-impl"]
fn sha2_128f_roundtrip() { roundtrip(Mode::Sha2_128f); }

#[test]
#[ignore = "luxcpp slhdsa c-abi NOTIMPL — tracked at #slhdsa-c-abi-impl"]
fn sha2_192f_roundtrip() { roundtrip(Mode::Sha2_192f); }

#[test]
#[ignore = "luxcpp slhdsa c-abi NOTIMPL — tracked at #slhdsa-c-abi-impl"]
fn sha2_256f_roundtrip() { roundtrip(Mode::Sha2_256f); }

#[test]
fn fips205_sizes_match() {
    assert_eq!(Mode::Sha2_128f.pk_len(), 32);
    assert_eq!(Mode::Sha2_128f.sk_len(), 64);
    assert_eq!(Mode::Sha2_128f.sig_len(), 17088);
    assert_eq!(Mode::Sha2_192f.pk_len(), 48);
    assert_eq!(Mode::Sha2_256f.sig_len(), 49856);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let mut pk = vec![0u8; Mode::Sha2_128f.pk_len()];
    let mut sk = vec![0u8; Mode::Sha2_128f.sk_len()];
    let seed = [0u8; 32];
    match keygen(Mode::Sha2_128f, &seed, &mut pk, &mut sk) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
