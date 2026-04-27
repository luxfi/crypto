// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Raw FFI bindings to luxcpp/crypto.
//
// Surface (Phase 1 + brand-neutral rename):
//   - secp256k1: ECDSA public-key recovery (single + batch)
//   - mldsa:     FIPS 204 ML-DSA (Dilithium) modes 2/3/5
//   - mlkem:     FIPS 203 ML-KEM (Kyber)     modes 2/3/5
//   - slhdsa:    FIPS 205 SLH-DSA (SPHINCS+) modes 2/3/5
//   - ed25519:   Ed25519 keygen / sign / verify
//   - keccak256: single-shot keccak256 (32-byte digest)
//
// All multi-byte buffers are big-endian unless noted. The C ABI is documented
// in `luxcpp/crypto/c-abi/lux_crypto.h` and the per-algorithm headers under
// `luxcpp/crypto/include/lux/crypto/*.h`.
//
// Symbols are brand-neutral. Rust constants do not carry the LUX_ prefix.

#![allow(non_camel_case_types)]

use core::ffi::c_int;

// ---------------------------------------------------------------------------
// secp256k1
// ---------------------------------------------------------------------------

/// Status codes returned by the secp256k1 C ABI.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secp256k1Status {
    Ok = 0,
    InvalidR = 1,
    InvalidS = 2,
    InvalidV = 3,
    NoSqrt = 4,
    AtInfinity = 5,
    NullArg = 6,
    BufferLen = 7,
}

impl Secp256k1Status {
    /// Convert a raw C `c_int` from a libcrypto secp256k1 call to the typed enum.
    /// Returns `None` for unknown values; callers can treat that as a bug.
    pub fn from_int(v: c_int) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidR),
            2 => Some(Self::InvalidS),
            3 => Some(Self::InvalidV),
            4 => Some(Self::NoSqrt),
            5 => Some(Self::AtInfinity),
            6 => Some(Self::NullArg),
            7 => Some(Self::BufferLen),
            _ => None,
        }
    }
}

// The canonical luxcpp/crypto C header declares brand-neutral symbols
// (`secp256k1_ecrecover`, `mldsa_*`, etc.). The current static archives at
// `build-canonical/<alg>/lib<alg>_cpu.a` still export those symbols with a
// `lux_` prefix until the next rebuild. We map both via `#[link_name]` so the
// Rust call surface stays brand-neutral and consumers see one canonical name.
extern "C" {
    /// Recover the 64-byte uncompressed public key from (hash, r, s, v).
    /// Returns one of the `Secp256k1Status` codes as `c_int`.
    #[link_name = "lux_secp256k1_ecrecover"]
    pub fn secp256k1_ecrecover(
        hash: *const u8,
        r: *const u8,
        s: *const u8,
        v: u8,
        pubkey: *mut u8,
    ) -> c_int;

    /// Batch ecrecover. inputs is n * 97 bytes (hash || r || s || v).
    /// pubkey_out is n * 64 bytes; status_out is n bytes.
    #[link_name = "lux_secp256k1_ecrecover_batch"]
    pub fn secp256k1_ecrecover_batch(
        inputs: *const u8,
        n: usize,
        pubkey_out: *mut u8,
        status_out: *mut u8,
    ) -> c_int;
}

// ---------------------------------------------------------------------------
// PQC mode (NIST level)
// ---------------------------------------------------------------------------

/// NIST security level: 2 = ML-KEM-512 / Dilithium2 / SLH-128s,
/// 3 = ML-KEM-768 / Dilithium3 / SLH-192s,
/// 5 = ML-KEM-1024 / Dilithium5 / SLH-256s.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistMode {
    Mode2 = 2,
    Mode3 = 3,
    Mode5 = 5,
}

/// Generic status returned by the unified C ABI (lux_crypto.h).
///
/// 0      => CRYPTO_OK
/// 1      => verify success (boolean ops); 0 is invalid signature
/// <0     => failure (negated errno-ish)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoStatus {
    Ok,
    VerifyOk,
    BadInput,
    BadLength,
    VerifyFail,
    Backend,
    NotImpl,
    Internal,
    Unknown(c_int),
}

impl CryptoStatus {
    pub fn from_int(v: c_int) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::VerifyOk,
            -1 => Self::BadInput,
            -2 => Self::BadLength,
            -3 => Self::VerifyFail,
            -4 => Self::Backend,
            -5 => Self::NotImpl,
            -6 => Self::Internal,
            other => Self::Unknown(other),
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok | Self::VerifyOk)
    }
}

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204)
// ---------------------------------------------------------------------------

pub mod mldsa {
    use super::{c_int, CryptoStatus, NistMode};

    extern "C" {
        #[link_name = "lux_mldsa_keygen"]
        fn mldsa_keygen(
            mode: c_int,
            seed: *const u8,
            pk: *mut u8,
            sk: *mut u8,
        ) -> c_int;
        #[link_name = "lux_mldsa_sign"]
        fn mldsa_sign(
            mode: c_int,
            sk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *mut u8,
            sig_len: *mut usize,
        ) -> c_int;
        #[link_name = "lux_mldsa_verify"]
        fn mldsa_verify(
            mode: c_int,
            pk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *const u8,
            sig_len: usize,
        ) -> c_int;
    }

    /// FIPS 204 sizes per NIST level (public key, secret key, signature).
    pub fn sizes(mode: NistMode) -> (usize, usize, usize) {
        match mode {
            NistMode::Mode2 => (1312, 2560, 2420),
            NistMode::Mode3 => (1952, 4032, 3309),
            NistMode::Mode5 => (2592, 4896, 4627),
        }
    }

    /// Generate a key pair from a 32-byte seed. Returns `(pk, sk)`.
    pub fn keygen(mode: NistMode, seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoStatus> {
        let (pk_len, sk_len, _) = sizes(mode);
        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];
        let rc = unsafe {
            mldsa_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok((pk, sk)) } else { Err(st) }
    }

    /// Sign a message with the given secret key. Returns the signature.
    pub fn sign(mode: NistMode, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoStatus> {
        let (_, sk_expect, sig_max) = sizes(mode);
        if sk.len() != sk_expect {
            return Err(CryptoStatus::BadLength);
        }
        let mut sig = vec![0u8; sig_max];
        let mut sig_len: usize = sig_max;
        let rc = unsafe {
            mldsa_sign(
                mode as c_int,
                sk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                &mut sig_len as *mut usize,
            )
        };
        let st = CryptoStatus::from_int(rc);
        if !st.is_ok() {
            return Err(st);
        }
        sig.truncate(sig_len);
        Ok(sig)
    }

    /// Verify a signature. Returns true on valid, false otherwise.
    /// I/O errors (bad length, etc.) are mapped to `false` to match the
    /// existing Rust crypto convention.
    pub fn verify(mode: NistMode, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let (pk_expect, _, _) = sizes(mode);
        if pk.len() != pk_expect {
            return false;
        }
        let rc = unsafe {
            mldsa_verify(
                mode as c_int,
                pk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        // C ABI: 1 = valid, 0 = invalid, <0 = error. Map invalid + error to false.
        rc == 1
    }
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203)
// ---------------------------------------------------------------------------

pub mod mlkem {
    use super::{c_int, CryptoStatus, NistMode};

    extern "C" {
        #[link_name = "lux_mlkem_keygen"]
        fn mlkem_keygen(
            mode: c_int,
            seed: *const u8,
            pk: *mut u8,
            sk: *mut u8,
        ) -> c_int;
        #[link_name = "lux_mlkem_encap"]
        fn mlkem_encap(
            mode: c_int,
            pk: *const u8,
            ct: *mut u8,
            ss: *mut u8,
        ) -> c_int;
        #[link_name = "lux_mlkem_decap"]
        fn mlkem_decap(
            mode: c_int,
            sk: *const u8,
            ct: *const u8,
            ss: *mut u8,
        ) -> c_int;
    }

    /// FIPS 203 sizes per NIST level (public key, secret key, ciphertext).
    /// Shared secret is always 32 bytes.
    pub fn sizes(mode: NistMode) -> (usize, usize, usize) {
        match mode {
            NistMode::Mode2 => (800, 1632, 768),
            NistMode::Mode3 => (1184, 2400, 1088),
            NistMode::Mode5 => (1568, 3168, 1568),
        }
    }

    /// Generate a key pair from a 32-byte seed.
    pub fn keygen(mode: NistMode, seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoStatus> {
        let (pk_len, sk_len, _) = sizes(mode);
        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];
        let rc = unsafe {
            mlkem_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok((pk, sk)) } else { Err(st) }
    }

    /// Encapsulate against a public key. Returns `(ciphertext, shared_secret)`.
    pub fn encap(mode: NistMode, pk: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoStatus> {
        let (pk_expect, _, ct_len) = sizes(mode);
        if pk.len() != pk_expect {
            return Err(CryptoStatus::BadLength);
        }
        let mut ct = vec![0u8; ct_len];
        let mut ss = [0u8; 32];
        let rc = unsafe {
            mlkem_encap(mode as c_int, pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr())
        };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok((ct, ss)) } else { Err(st) }
    }

    /// Decapsulate a ciphertext with the secret key.
    pub fn decap(mode: NistMode, sk: &[u8], ct: &[u8]) -> Result<[u8; 32], CryptoStatus> {
        let (_, sk_expect, ct_expect) = sizes(mode);
        if sk.len() != sk_expect || ct.len() != ct_expect {
            return Err(CryptoStatus::BadLength);
        }
        let mut ss = [0u8; 32];
        let rc = unsafe {
            mlkem_decap(mode as c_int, sk.as_ptr(), ct.as_ptr(), ss.as_mut_ptr())
        };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok(ss) } else { Err(st) }
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA (FIPS 205)
// ---------------------------------------------------------------------------

pub mod slhdsa {
    use super::{c_int, CryptoStatus, NistMode};

    extern "C" {
        #[link_name = "lux_slhdsa_keygen"]
        fn slhdsa_keygen(
            mode: c_int,
            seed: *const u8,
            pk: *mut u8,
            sk: *mut u8,
        ) -> c_int;
        #[link_name = "lux_slhdsa_sign"]
        fn slhdsa_sign(
            mode: c_int,
            sk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *mut u8,
            sig_len: *mut usize,
        ) -> c_int;
        #[link_name = "lux_slhdsa_verify"]
        fn slhdsa_verify(
            mode: c_int,
            pk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *const u8,
            sig_len: usize,
        ) -> c_int;
    }

    /// FIPS 205 sizes for the small variants (pk, sk, max_signature).
    pub fn sizes(mode: NistMode) -> (usize, usize, usize) {
        match mode {
            NistMode::Mode2 => (32, 64, 7856),
            NistMode::Mode3 => (48, 96, 16224),
            NistMode::Mode5 => (64, 128, 29792),
        }
    }

    pub fn keygen(mode: NistMode, seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoStatus> {
        let (pk_len, sk_len, _) = sizes(mode);
        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];
        let rc = unsafe {
            slhdsa_keygen(mode as c_int, seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok((pk, sk)) } else { Err(st) }
    }

    pub fn sign(mode: NistMode, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoStatus> {
        let (_, sk_expect, sig_max) = sizes(mode);
        if sk.len() != sk_expect {
            return Err(CryptoStatus::BadLength);
        }
        let mut sig = vec![0u8; sig_max];
        let mut sig_len: usize = sig_max;
        let rc = unsafe {
            slhdsa_sign(
                mode as c_int,
                sk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                &mut sig_len as *mut usize,
            )
        };
        let st = CryptoStatus::from_int(rc);
        if !st.is_ok() {
            return Err(st);
        }
        sig.truncate(sig_len);
        Ok(sig)
    }

    pub fn verify(mode: NistMode, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let (pk_expect, _, _) = sizes(mode);
        if pk.len() != pk_expect {
            return false;
        }
        let rc = unsafe {
            slhdsa_verify(
                mode as c_int,
                pk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        rc == 1
    }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

pub mod ed25519 {
    use super::{c_int, CryptoStatus};

    extern "C" {
        #[link_name = "lux_ed25519_keygen"]
        fn ed25519_keygen(seed: *const u8, sk: *mut u8, pk: *mut u8) -> c_int;
        #[link_name = "lux_ed25519_sign"]
        fn ed25519_sign(
            sk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *mut u8,
        ) -> c_int;
        #[link_name = "lux_ed25519_verify"]
        fn ed25519_verify(
            pk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *const u8,
        ) -> c_int;
    }

    /// Generate an Ed25519 key pair from a 32-byte seed. Returns `(sk, pk)`.
    pub fn keygen(seed: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoStatus> {
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 32];
        let rc = unsafe { ed25519_keygen(seed.as_ptr(), sk.as_mut_ptr(), pk.as_mut_ptr()) };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok((sk, pk)) } else { Err(st) }
    }

    /// Sign a message. Returns a 64-byte signature.
    pub fn sign(sk: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], CryptoStatus> {
        let mut sig = [0u8; 64];
        let rc = unsafe {
            ed25519_sign(sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr())
        };
        let st = CryptoStatus::from_int(rc);
        if st.is_ok() { Ok(sig) } else { Err(st) }
    }

    /// Verify a 64-byte signature. Returns true on valid.
    pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let rc = unsafe {
            ed25519_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr())
        };
        rc == 1
    }
}

// ---------------------------------------------------------------------------
// keccak256
// ---------------------------------------------------------------------------

pub mod keccak256 {
    extern "C" {
        // The C ABI declares this as `void` in lux/crypto/keccak.h.
        #[link_name = "lux_keccak256"]
        fn keccak256(input: *const u8, input_len: usize, output: *mut u8);
    }

    /// Compute the keccak256 digest of `input`. Always returns a 32-byte digest.
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            keccak256(input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time symbol check. The actual smoke test is in luxfi/accel
    // (Go side) and the C++ test harness; here we just confirm linkage.
    #[test]
    fn link_secp256k1() {
        let _f: unsafe extern "C" fn(*const u8, *const u8, *const u8, u8, *mut u8) -> i32 =
            secp256k1_ecrecover;
    }

    #[test]
    fn status_from_int() {
        assert_eq!(Secp256k1Status::from_int(0), Some(Secp256k1Status::Ok));
        assert_eq!(Secp256k1Status::from_int(7), Some(Secp256k1Status::BufferLen));
        assert_eq!(Secp256k1Status::from_int(99), None);
    }

    #[test]
    fn crypto_status_from_int() {
        assert!(CryptoStatus::from_int(0).is_ok());
        assert!(CryptoStatus::from_int(1).is_ok());
        assert!(!CryptoStatus::from_int(-1).is_ok());
    }

    #[test]
    fn sizes_ml_dsa() {
        assert_eq!(mldsa::sizes(NistMode::Mode3), (1952, 4032, 3309));
    }

    #[test]
    fn sizes_ml_kem() {
        assert_eq!(mlkem::sizes(NistMode::Mode3), (1184, 2400, 1088));
    }

    #[test]
    fn sizes_slh_dsa() {
        assert_eq!(slhdsa::sizes(NistMode::Mode3), (48, 96, 16224));
    }
}
