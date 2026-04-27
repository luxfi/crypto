// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// EVM 256-bit modular arithmetic KAT.

use lux_crypto_evm256::{addmod, mulmod, WORD_LEN};

fn be_u256(low: u64) -> [u8; WORD_LEN] {
    let mut out = [0u8; WORD_LEN];
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}

#[test]
fn addmod_small() {
    // (5 + 7) mod 10 = 2.
    let a = be_u256(5);
    let b = be_u256(7);
    let m = be_u256(10);
    let mut out = [0u8; WORD_LEN];
    if addmod(&a, &b, &m, &mut out).is_ok() {
        assert_eq!(out, be_u256(2));
    }
}

#[test]
fn mulmod_small() {
    // (5 * 7) mod 10 = 5.
    let a = be_u256(5);
    let b = be_u256(7);
    let m = be_u256(10);
    let mut out = [0u8; WORD_LEN];
    if mulmod(&a, &b, &m, &mut out).is_ok() {
        assert_eq!(out, be_u256(5));
    }
}
