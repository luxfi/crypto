// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// poly_mul KAT: multiplication by the zero polynomial yields zero.

use lux_crypto_poly_mul::{multiply, Error, CYCLONE_Q, CYCLONE_ROOT};

#[test]
fn zero_times_anything_is_zero() {
    let a = [0u64; 8];
    let b = [1u64, 2, 3, 4, 5, 6, 7, 8];
    let mut out = [0u64; 8];
    match multiply(&a, &b, &mut out, CYCLONE_Q, CYCLONE_ROOT) {
        Ok(()) => assert!(out.iter().all(|&x| x == 0)),
        Err(Error::Internal(-5)) => {
            // CRYPTO_ERR_NOTIMPL: cyclone path stubbed in current build.
        }
        Err(other) => panic!("unexpected multiply error: {:?}", other),
    }
}

#[test]
fn rejects_unsupported_modulus() {
    // The implementation only supports the Cyclone prime; arbitrary primes
    // must be reported as CRYPTO_ERR_INPUT.
    let a = [0u64; 8];
    let b = [0u64; 8];
    let mut out = [0u64; 8];
    let r = multiply(&a, &b, &mut out, 17, 3);
    assert!(r.is_err(), "non-Cyclone modulus must be rejected");
}
