// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-lamport: canonical Rust binding for Lux Lamport one-time
// signatures over SHA-256 (Lamport 1979).
//
// Sizes (SHA-256 variant):
//   secret key bytes  = 16384  (= 2 * 256 * 32)
//   public key bytes  = 16384
//   signature bytes   =  8192  (= 256 * 32)
//
// IMPORTANT: A Lamport-SHA256 secret key MUST NOT be reused. Reuse of the
// secret key for two distinct messages allows the recovery of the entire
// secret. The C-ABI does not enforce single-use; the caller is responsible.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn lamport_keygen(seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;
    fn lamport_sign(sk: *const u8, msg32: *const u8, sig: *mut u8) -> c_int;
    fn lamport_verify(pk: *const u8, msg32: *const u8, sig: *const u8) -> c_int;
}

/// Length of the Lamport public key in bytes (512 hashes of 32 bytes).
pub const PUBLIC_KEY_LEN: usize = 16384;
/// Length of the Lamport secret key in bytes (512 secrets of 32 bytes).
pub const SECRET_KEY_LEN: usize = 16384;
/// Length of a Lamport signature in bytes (256 selected secrets of 32 bytes).
pub const SIGNATURE_LEN: usize = 8192;
/// Length of the message-hash input (Lamport signs a 32-byte digest).
pub const MSG_HASH_LEN: usize = 32;
/// Length of the keygen seed in bytes.
pub const SEED_LEN: usize = 32;

/// Errors returned by the Lamport C-ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// One of the input pointers was NULL.
    BadInput,
    /// The signature did not verify.
    VerifyFail,
    /// The C-ABI returned an unexpected status.
    Internal(c_int),
}

/// Generate a Lamport keypair from a 32-byte seed via the canonical KDF
/// (`SHA-256("lamport-kat/v1\0" || seed)` then iterated SHA-256). Returns
/// `(pk, sk)` as boxed buffers because each is 16 KiB.
pub fn keygen(seed: &[u8; SEED_LEN]) -> Result<(Box<[u8; PUBLIC_KEY_LEN]>, Box<[u8; SECRET_KEY_LEN]>), Error> {
    let mut pk = Box::new([0u8; PUBLIC_KEY_LEN]);
    let mut sk = Box::new([0u8; SECRET_KEY_LEN]);
    // SAFETY: All buffers are sized to the C-ABI's documented widths.
    let rc = unsafe { lamport_keygen(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) };
    match rc {
        0 => Ok((pk, sk)),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Sign a 32-byte message digest with a Lamport secret key. The secret key
/// MUST NOT be reused.
pub fn sign(
    sk: &[u8; SECRET_KEY_LEN],
    msg32: &[u8; MSG_HASH_LEN],
) -> Result<Box<[u8; SIGNATURE_LEN]>, Error> {
    let mut sig = Box::new([0u8; SIGNATURE_LEN]);
    // SAFETY: Buffers sized to C-ABI contract.
    let rc = unsafe { lamport_sign(sk.as_ptr(), msg32.as_ptr(), sig.as_mut_ptr()) };
    match rc {
        0 => Ok(sig),
        -1 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// Verify a Lamport signature against a 32-byte message hash and public key.
pub fn verify(
    pk: &[u8; PUBLIC_KEY_LEN],
    msg32: &[u8; MSG_HASH_LEN],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    // SAFETY: Buffers sized to C-ABI contract.
    let rc = unsafe { lamport_verify(pk.as_ptr(), msg32.as_ptr(), sig.as_ptr()) };
    match rc {
        0 => Ok(()),
        -1 => Err(Error::BadInput),
        -3 => Err(Error::VerifyFail),
        x => Err(Error::Internal(x)),
    }
}
