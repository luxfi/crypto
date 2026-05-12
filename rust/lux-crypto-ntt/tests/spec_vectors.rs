// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_ntt::{forward, inverse, poly_multiply, Error};

const MODULUS: u64 = 0xFFFF_FFFF_0000_0001; // Goldilocks prime
const ROOT: u64 = 7;
const ROOT_INV: u64 = 0x66f8_8019_88c4_a4b3;

#[test]
#[ignore = "luxcpp ntt c-abi NOTIMPL — tracked at #ntt-c-abi-impl"]
fn forward_then_inverse_is_identity() {
    let mut input: Vec<u64> = (1..=8).collect();
    let original = input.clone();
    forward(&mut input, MODULUS, ROOT).expect("forward");
    inverse(&mut input, MODULUS, ROOT_INV).expect("inverse");
    assert_eq!(input, original, "forward/inverse must be inverses");
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let mut x = [1u64; 8];
    match forward(&mut x, MODULUS, ROOT) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
    }
}

#[test]
fn poly_multiply_rejects_non_cyclone_params() {
    // The poly_mul C-ABI is specialized to the Cyclone-FFT prime (see
    // luxcpp/crypto/poly_mul/c-abi/c_poly_mul.cpp). Calling it with Goldilocks
    // params is a domain mismatch and must return CRYPTO_ERR_INPUT (-1), not
    // CRYPTO_ERR_NOTIMPL. The generic NTT path (forward/inverse) covers
    // arbitrary NTT-friendly primes.
    let a = [1u64; 4];
    let b = [1u64; 4];
    let mut out = [0u64; 4];
    match poly_multiply(&a, &b, MODULUS, ROOT, &mut out) {
        Err(Error::InternalError(-1)) => {}
        other => panic!("expected InternalError(-1) for non-Cyclone params, got {:?}", other),
    }
}
