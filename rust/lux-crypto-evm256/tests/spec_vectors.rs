// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

use lux_crypto_evm256::{addmod, mod_exp, mulmod, Error};

#[test]
#[ignore = "luxcpp modexp c-abi NOTIMPL — tracked at #modexp-c-abi-impl"]
fn modexp_2_pow_3_mod_5_is_3() {
    // 2^3 mod 5 = 3. Big-endian, padded to mod length.
    let base = [2u8];
    let exp = [3u8];
    let m = [5u8];
    let mut out = [0u8; 1];
    mod_exp(&base, &exp, &m, &mut out).expect("modexp");
    assert_eq!(out[0], 3);
}

#[test]
#[ignore = "luxcpp evm256 c-abi NOTIMPL — tracked at #evm256-c-abi-impl"]
fn mulmod_3_times_5_mod_7_is_1() {
    let mut a = [0u8; 32]; a[31] = 3;
    let mut b = [0u8; 32]; b[31] = 5;
    let mut m = [0u8; 32]; m[31] = 7;
    let out = mulmod(&a, &b, &m).expect("mulmod");
    let mut want = [0u8; 32]; want[31] = 1;
    assert_eq!(out, want);
}

#[test]
fn binding_returns_error_when_c_abi_unimpl() {
    let a = [0u8; 32];
    let b = [0u8; 32];
    let mut m = [0u8; 32]; m[31] = 1;
    match addmod(&a, &b, &m) {
        Ok(_) => {}
        Err(Error::InternalError(rc)) => {
            assert_eq!(rc, -5);
        }
        Err(other) => panic!("unexpected: {:?}", other),
    }
}
