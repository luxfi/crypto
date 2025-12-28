// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// ML-KEM (FIPS 203) binding smoke test.

use lux_crypto_mlkem::{decap, encap, keygen, Error, Mode, SS_LEN};

#[test]
fn keygen_encap_decap_roundtrip_or_notimpl_k768() {
    let mode = Mode::K768;
    let seed = [0x33u8; 32];
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];

    match keygen(mode, &seed, &mut pk, &mut sk) {
        Ok(()) => {
            let mut ct = vec![0u8; mode.ct_len()];
            let mut ss_a = [0u8; SS_LEN];
            let mut ss_b = [0u8; SS_LEN];
            encap(mode, &pk, &mut ct, &mut ss_a).expect("encap after keygen");
            decap(mode, &sk, &ct, &mut ss_b).expect("decap after encap");
            assert_eq!(ss_a, ss_b, "shared secret must match across encap/decap");
        }
        Err(Error::Internal(-5)) => {
            let mut ct = vec![0u8; mode.ct_len()];
            let mut ss = [0u8; SS_LEN];
            assert!(matches!(
                encap(mode, &pk, &mut ct, &mut ss),
                Err(Error::Internal(-5))
            ));
        }
        Err(other) => panic!("unexpected keygen error: {:?}", other),
    }
}
