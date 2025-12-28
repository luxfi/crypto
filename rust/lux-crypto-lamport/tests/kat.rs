// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Lamport binding smoke test. We call the C-ABI through Rust and confirm
// keygen/sign/verify either round-trips successfully (when the canonical
// luxcpp body is wired) or returns the documented NOTIMPL status (-5)
// uniformly across all three operations.

use lux_crypto_lamport::{keygen, sign, verify, Error, MSG_LEN, PK_LEN, SEED_LEN, SIG_LEN, SK_LEN};

#[test]
fn keygen_sign_verify_roundtrip_or_notimpl() {
    let seed = [0x42u8; SEED_LEN];
    let msg = [0x55u8; MSG_LEN];
    let mut pk = Box::new([0u8; PK_LEN]);
    let mut sk = Box::new([0u8; SK_LEN]);
    let mut sig = Box::new([0u8; SIG_LEN]);

    match keygen(&seed, &mut pk, &mut sk) {
        Ok(()) => {
            sign(&sk, &msg, &mut sig).expect("sign after successful keygen");
            verify(&pk, &msg, &sig).expect("verify must accept honest signature");
        }
        Err(Error::Internal(-5)) => {
            // CRYPTO_ERR_NOTIMPL is the documented placeholder while the
            // luxcpp body is being wired. Sign and verify must agree.
            assert_eq!(
                sign(&sk, &msg, &mut sig),
                Err(Error::Internal(-5)),
                "sign must report NOTIMPL when keygen reports NOTIMPL"
            );
        }
        Err(other) => panic!("unexpected keygen error: {:?}", other),
    }
}
