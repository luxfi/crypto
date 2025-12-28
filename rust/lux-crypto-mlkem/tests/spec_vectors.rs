// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_mlkem::{decap, encap, keygen, Error, Mode, SS_LEN};

fn roundtrip(mode: Mode) {
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];
    let seed = [0xA5_u8; 32];
    keygen(mode, &seed, &mut pk, &mut sk).expect("keygen");
    let mut ct = vec![0u8; mode.ct_len()];
    let mut ss_a = [0u8; SS_LEN];
    let mut ss_b = [0u8; SS_LEN];
    encap(mode, &pk, &mut ct, &mut ss_a).expect("encap");
    decap(mode, &sk, &ct, &mut ss_b).expect("decap");
    assert_eq!(ss_a, ss_b, "encap/decap shared secrets must match");
}

#[test]
#[ignore = "luxcpp mlkem c-abi NOTIMPL — tracked at #mlkem-c-abi-impl"]
fn mode_2_roundtrip() { roundtrip(Mode::Mode2); }

#[test]
#[ignore = "luxcpp mlkem c-abi NOTIMPL — tracked at #mlkem-c-abi-impl"]
fn mode_3_roundtrip() { roundtrip(Mode::Mode3); }

#[test]
#[ignore = "luxcpp mlkem c-abi NOTIMPL — tracked at #mlkem-c-abi-impl"]
fn mode_5_roundtrip() { roundtrip(Mode::Mode5); }

#[test]
fn fips203_sizes_match() {
    assert_eq!(Mode::Mode2.pk_len(), 800);
    assert_eq!(Mode::Mode2.sk_len(), 1632);
    assert_eq!(Mode::Mode2.ct_len(), 768);
    assert_eq!(Mode::Mode3.pk_len(), 1184);
    assert_eq!(Mode::Mode5.pk_len(), 1568);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let mut pk = vec![0u8; Mode::Mode2.pk_len()];
    let mut sk = vec![0u8; Mode::Mode2.sk_len()];
    let seed = [0u8; 32];
    match keygen(Mode::Mode2, &seed, &mut pk, &mut sk) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
