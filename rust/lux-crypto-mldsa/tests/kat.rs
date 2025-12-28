// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// ML-DSA (FIPS 204) binding smoke test. The luxcpp body currently returns
// CRYPTO_ERR_NOTIMPL (-5); this test confirms the C-ABI is reachable through
// Rust and round-trips correctly when wired.

use lux_crypto_mldsa::{keygen, sign, verify, Error, Mode};

#[test]
fn keygen_sign_verify_roundtrip_or_notimpl_m65() {
    let mode = Mode::M65;
    let seed = [0x7Au8; 32];
    let mut pk = vec![0u8; mode.pk_len()];
    let mut sk = vec![0u8; mode.sk_len()];

    match keygen(mode, &seed, &mut pk, &mut sk) {
        Ok(()) => {
            let mut sig = vec![0u8; mode.sig_len()];
            let n = sign(mode, &sk, b"lux-mldsa-binding-kat", &mut sig)
                .expect("sign after keygen");
            verify(mode, &pk, b"lux-mldsa-binding-kat", &sig[..n])
                .expect("verify accepts honest signature");
        }
        Err(Error::Internal(-5)) => {
            // CRYPTO_ERR_NOTIMPL; sign and verify must agree.
            let mut sig = vec![0u8; mode.sig_len()];
            assert!(matches!(
                sign(mode, &sk, b"x", &mut sig),
                Err(Error::Internal(-5))
            ));
        }
        Err(other) => panic!("unexpected keygen error: {:?}", other),
    }
}
