// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector tests for lux-crypto-poly_mul. Mirrors the Go reference's KAT
// schedule (lcg seed_a / seed_b -> a / b -> negacyclic c -> sum/first/last).
// Cross-references luxcpp/crypto/poly_mul/test/vectors/poly_mul_kat.json.

use lux_crypto_poly_mul::{multiply, Q};

fn lcg(seed: u64, n: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(n);
    let mut state = seed;
    for _ in 0..n {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push(state % Q);
    }
    out
}

// 10 KAT cases — same (n, seed_a, seed_b, sum, first, last) as
// /Users/z/work/lux/crypto/poly_mul/poly_mul_test.go::TestKATs.
const KATS: &[(usize, u64, u64, u64, u64, u64)] = &[
    (    2, 0x1,        0x2,        567_996_115, 371_012_399, 196_983_716),
    (    4, 0x64,       0xc8,       935_898_137, 410_827_071, 376_044_324),
    (    8, 0x4d2,      0x162e,      48_246_169, 673_146_415, 767_542_882),
    (   16, 0xdead_beef,0xcafe_babe,590_901_354,  41_636_199, 860_993_788),
    (   32, 0x7,        0xd,         72_828_809, 392_054_258,  84_461_645),
    (   64, 0xb,        0x11,       933_631_914, 967_956_798, 522_099_145),
    (  128, 0x13,       0x17,       443_591_268, 429_303_763, 461_383_520),
    (  256, 0x1,        0x2,         78_388_485, 359_306_289, 229_818_328),
    (  512, 0x1f,       0x25,       723_079_964, 641_254_315, 816_782_592),
    ( 1024, 0x29,       0x2b,       308_246_040,   8_552_215, 931_224_377),
];

fn check(c: &[u64], want_sum: u64, want_first: u64, want_last: u64) {
    let mut sum = 0u64;
    for &v in c {
        assert!(v < Q, "out-of-range output {v} (Q={Q})");
        sum = (sum + v) % Q;
    }
    assert_eq!(sum, want_sum, "sum mismatch");
    assert_eq!(c[0], want_first, "first mismatch");
    assert_eq!(c[c.len() - 1], want_last, "last mismatch");
}

#[test]
fn kat_table() {
    for &(n, seed_a, seed_b, sum, first, last) in KATS {
        let a = lcg(seed_a, n);
        let b = lcg(seed_b, n);
        let c = multiply(&a, &b).expect("multiply");
        assert_eq!(c.len(), n);
        check(&c, sum, first, last);
    }
}

// Hand-written negacyclic case from the Go test:
// (1 + 2X + 3X^2 + 4X^3) * (5 + 6X + 7X^2 + 8X^3) mod (X^4 + 1)
// = 998244297 + 998244317 X + 2 X^2 + 60 X^3
#[test]
fn negacyclic_handwritten() {
    let a: Vec<u64> = vec![1, 2, 3, 4];
    let b: Vec<u64> = vec![5, 6, 7, 8];
    let want: Vec<u64> = vec![998_244_297, 998_244_317, 2, 60];
    let c = multiply(&a, &b).unwrap();
    assert_eq!(c, want);
}

#[test]
fn rejects_length_mismatch() {
    assert!(multiply(&[1u64, 2], &[1u64, 2, 3]).is_err());
}

#[test]
fn rejects_empty() {
    assert!(multiply(&[], &[]).is_err());
}
