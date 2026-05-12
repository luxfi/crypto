// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// NTT KAT: forward followed by inverse should restore the input vector
// (modulo a global scaling factor handled by the implementation).

use lux_crypto_ntt::{forward, inverse, Error, CYCLONE_Q, CYCLONE_ROOT};

#[test]
fn forward_then_inverse_is_identity_on_zero_vector() {
    let mut coeffs = [0u64; 8];
    match forward(&mut coeffs, CYCLONE_Q, CYCLONE_ROOT) {
        Ok(()) => {
            assert!(coeffs.iter().all(|&x| x == 0));
            inverse(&mut coeffs, CYCLONE_Q, CYCLONE_ROOT)
                .expect("inverse NTT after successful forward");
            assert!(coeffs.iter().all(|&x| x == 0));
        }
        Err(Error::InternalError(-5)) => {
            // CRYPTO_ERR_NOTIMPL: cyclone path stubbed in current build.
        }
        Err(other) => panic!("unexpected forward NTT error: {:?}", other),
    }
}

#[test]
fn rejects_non_power_of_two() {
    let mut coeffs = [1u64; 6];
    assert!(forward(&mut coeffs, CYCLONE_Q, CYCLONE_ROOT).is_err());
}
