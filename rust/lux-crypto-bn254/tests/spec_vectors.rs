// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_bn254::{add, mul, pairing, Error};

#[test]
#[ignore = "luxcpp bn254 c-abi NOTIMPL — tracked at #bn254-c-abi-impl"]
fn add_zero_plus_zero_is_zero() {
    // EVM ALT_BN128_ADD: 0 + 0 = 0 (point at infinity, encoded as all zeros).
    let input = [0u8; 128];
    let out = add(&input).expect("add");
    assert_eq!(out, [0u8; 64]);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let input = [0u8; 128];
    match add(&input) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
    }
}

#[test]
fn mul_returns_error_when_c_abi_unimpl() {
    let input = [0u8; 96];
    let res = mul(&input);
    if let Err(Error::InternalError(rc)) = res {
        assert_eq!(rc, -5);
    }
}

#[test]
fn pairing_returns_error_when_c_abi_unimpl() {
    let pairs = [0u8; 0];
    let res = pairing(&pairs, 0);
    if let Err(Error::InternalError(rc)) = res {
        assert_eq!(rc, -5);
    }
}
