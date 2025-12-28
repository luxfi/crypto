// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_mldsa::{keygen, sign, verify, Error, Mode};

fn roundtrip(mode: Mode) {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    let seed = [0xA5_u8; 32];
    keygen(mode, &seed, &mut pk, &mut sk).expect("keygen");
    let mut sig = vec![0u8; mode.sig_len()];
    let n = sign(mode, &sk, b"ML-DSA roundtrip", &mut sig).expect("sign");
    verify(mode, &pk, b"ML-DSA roundtrip", &sig[..n]).expect("verify");
}

#[test]
#[ignore = "luxcpp mldsa c-abi NOTIMPL — tracked at #mldsa-c-abi-impl"]
fn mode_2_roundtrip() { roundtrip(Mode::Mode2); }

#[test]
#[ignore = "luxcpp mldsa c-abi NOTIMPL — tracked at #mldsa-c-abi-impl"]
fn mode_3_roundtrip() { roundtrip(Mode::Mode3); }

#[test]
#[ignore = "luxcpp mldsa c-abi NOTIMPL — tracked at #mldsa-c-abi-impl"]
fn mode_5_roundtrip() { roundtrip(Mode::Mode5); }

#[test]
fn fips204_sizes_match() {
    assert_eq!(Mode::Mode2.pk_len(), 1312);
    assert_eq!(Mode::Mode2.sk_len(), 2560);
    assert_eq!(Mode::Mode2.sig_len(), 2420);
    assert_eq!(Mode::Mode3.pk_len(), 1952);
    assert_eq!(Mode::Mode3.sk_len(), 4032);
    assert_eq!(Mode::Mode3.sig_len(), 3309);
    assert_eq!(Mode::Mode5.pk_len(), 2592);
    assert_eq!(Mode::Mode5.sk_len(), 4896);
    assert_eq!(Mode::Mode5.sig_len(), 4627);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let mut pk = vec![0u8; Mode::Mode2.pk_len()];
    let mut sk = vec![0u8; Mode::Mode2.sk_len()];
    let seed = [0u8; 32];
    match keygen(Mode::Mode2, &seed, &mut pk, &mut sk) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
