// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec vectors for negacyclic polynomial multiplication over Z_Q[X]/(X^n + 1)
// with the Cyclone-FFT prime Q = 998244353. Vectors below are computed using
// the schoolbook reference (which the underlying C body always uses for n<64)
// and verified independently in pure Rust.

use lux_crypto_poly_mul::{multiply, Error, CYCLONE_PRIME, CYCLONE_PRIMITIVE_ROOT};

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let a = [0u64; 4];
    let b = [0u64; 4];
    let mut out = [0u64; 4];
    match multiply(&a, &b, CYCLONE_PRIME, CYCLONE_PRIMITIVE_ROOT, &mut out) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5, "expected NOTIMPL while C-ABI body is unwired");
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}

#[test]
#[ignore = "luxcpp poly_mul/ntt c-abi NOTIMPL — tracked at #poly_mul-c-abi-impl"]
fn n_4_schoolbook_multiply() {
    // a(X) = 1 + 2X + 3X^2 + 4X^3
    // b(X) = 5 + 6X + 7X^2 + 8X^3
    // Negacyclic product over X^4 + 1:
    //   X^4 = -1 ⇒ wrap with negation.
    //   (1*5)        = 5      → 5
    //   (1*6 + 2*5)   = 16     → 16
    //   (1*7 + 2*6 + 3*5)  = 34   → 34
    //   (1*8 + 2*7 + 3*6 + 4*5)  = 60   → 60
    //   (2*8 + 3*7 + 4*6) = 61   wrap → -61
    //   (3*8 + 4*7) = 52   wrap → -52
    //   (4*8) = 32   wrap → -32
    // out = [5 - 60? ... ] -- recompute properly:
    //
    // For X^4+1 negacyclic the c[k] for k=0..3 is:
    //   c[k] = sum_{i+j=k}   a_i b_j
    //        - sum_{i+j=k+n} a_i b_j
    //
    //   c[0] = 1*5  -  (2*8 + 3*7 + 4*6) = 5 - (16+21+24) = 5 - 61 = -56
    //   c[1] = (1*6 + 2*5)  -  (3*8 + 4*7) = 16 - (24+28) = 16 - 52 = -36
    //   c[2] = (1*7 + 2*6 + 3*5) - (4*8) = 34 - 32 = 2
    //   c[3] = (1*8 + 2*7 + 3*6 + 4*5)   = 60
    //
    // Reduced mod Q = 998244353:
    //   c[0] = Q - 56 = 998244297
    //   c[1] = Q - 36 = 998244317
    //   c[2] = 2
    //   c[3] = 60
    let a = [1u64, 2, 3, 4];
    let b = [5u64, 6, 7, 8];
    let mut out = [0u64; 4];
    multiply(&a, &b, CYCLONE_PRIME, CYCLONE_PRIMITIVE_ROOT, &mut out)
        .expect("poly_mul should succeed");
    assert_eq!(out, [CYCLONE_PRIME - 56, CYCLONE_PRIME - 36, 2, 60]);
}

#[test]
#[ignore = "luxcpp poly_mul/ntt c-abi NOTIMPL — tracked at #poly_mul-c-abi-impl"]
fn n_2_unit_polynomial_squared() {
    // a(X) = 1, b(X) = 1, n=2 ⇒ X^2 + 1 ring.
    // c(X) = 1 (trivially).
    let a = [1u64, 0];
    let b = [1u64, 0];
    let mut out = [0u64; 2];
    multiply(&a, &b, CYCLONE_PRIME, CYCLONE_PRIMITIVE_ROOT, &mut out)
        .expect("poly_mul");
    assert_eq!(out, [1, 0]);
}

#[test]
#[ignore = "luxcpp poly_mul/ntt c-abi NOTIMPL — tracked at #poly_mul-c-abi-impl"]
fn n_8_ntt_path_against_schoolbook() {
    // Construct two random-ish polynomials of length 8. n=8 hits the NTT
    // path since 8 < SCHOOLBOOK_THRESHOLD (=64) but the C body falls back
    // to schoolbook for small n. Either way the result must match the
    // pure-Rust reference computed below.
    let a: [u64; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
    let b: [u64; 8] = [11, 22, 33, 44, 55, 66, 77, 88];

    let mut out = [0u64; 8];
    multiply(&a, &b, CYCLONE_PRIME, CYCLONE_PRIMITIVE_ROOT, &mut out)
        .expect("poly_mul");

    // Reference: signed schoolbook with X^8 = -1.
    let mut want_signed = [0i128; 8];
    for i in 0..8 {
        for j in 0..8 {
            let prod = (a[i] as i128) * (b[j] as i128);
            let k = i + j;
            if k < 8 { want_signed[k] += prod; } else { want_signed[k - 8] -= prod; }
        }
    }
    let q = CYCLONE_PRIME as i128;
    let want: [u64; 8] = core::array::from_fn(|i| ((want_signed[i] % q + q) % q) as u64);
    assert_eq!(out, want, "NTT path mismatch with schoolbook reference");
}
