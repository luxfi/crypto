// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux-crypto-bls: canonical Rust binding for the Lux BLS12-381 IRTF
// signature C-ABI (draft-irtf-cfrg-bls-signature-05).
//
// Ciphersuite: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ — Ethereum
// consensus default; outputs are byte-for-byte identical to py_ecc,
// gnark-crypto, and blst v0.3.15.
//
// Pubkeys live on G1 (48-byte Zcash-compressed). Signatures live on G2
// (96-byte Zcash-compressed). The C-ABI is in
// luxcpp/crypto/bls/c-abi/c_bls_signature.{cpp,h}; bodies are in
// cpp/bls_signature.cpp which PRIVATE-links blst.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

extern "C" {
    fn bls12_381_keygen(seed: *const u8, sk: *mut u8) -> c_int;
    fn bls12_381_sk_to_pk(sk: *const u8, pk: *mut u8) -> c_int;
    fn bls12_381_sign(
        sk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *mut u8,
    ) -> c_int;
    fn bls12_381_verify(
        pk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
    ) -> c_int;
    fn bls12_381_aggregate_pubkeys(
        pks: *const u8,
        n: usize,
        agg_pk: *mut u8,
    ) -> c_int;
    fn bls12_381_aggregate_sigs(
        sigs: *const u8,
        n: usize,
        agg_sig: *mut u8,
    ) -> c_int;
    fn bls12_381_fast_aggregate_verify(
        pks: *const u8,
        n: usize,
        msg: *const u8,
        msg_len: usize,
        agg_sig: *const u8,
    ) -> c_int;
    fn bls12_381_aggregate_verify_distinct(
        pks: *const u8,
        n: usize,
        msgs_flat: *const u8,
        msg_lens: *const usize,
        agg_sig: *const u8,
    ) -> c_int;
}

/// Length of a BLS12-381 secret key (32 bytes, big-endian scalar in [1, r)).
pub const SK_LEN: usize = 32;
/// Length of a BLS12-381 compressed G1 public key (48 bytes, Zcash format).
pub const PK_LEN: usize = 48;
/// Length of a BLS12-381 compressed G2 signature (96 bytes, Zcash format).
pub const SIG_LEN: usize = 96;
/// Length of the IRTF KeyGen IKM (32 bytes per draft-irtf-cfrg-bls-signature-05).
pub const IKM_LEN: usize = 32;

/// Errors returned by the BLS12-381 signature primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input buffer length mismatch, null pointer, or malformed compression.
    BadInput,
    /// Verification rejected the signature.
    VerifyFail,
    /// The C-ABI returned an unexpected status.
    Internal(c_int),
}

fn rc_to_result(rc: c_int) -> Result<(), Error> {
    match rc {
        0 => Ok(()),
        1 => Err(Error::VerifyFail),
        -1 | -2 => Err(Error::BadInput),
        x => Err(Error::Internal(x)),
    }
}

/// IRTF KeyGen (§2.3): derive a 32-byte secret key from a 32-byte IKM.
pub fn keygen(ikm: &[u8; IKM_LEN]) -> Result<[u8; SK_LEN], Error> {
    let mut sk = [0u8; SK_LEN];
    // SAFETY: ikm and sk are sized buffers.
    let rc = unsafe { bls12_381_keygen(ikm.as_ptr(), sk.as_mut_ptr()) };
    rc_to_result(rc).map(|()| sk)
}

/// Derive the 48-byte compressed G1 public key from the 32-byte secret key.
pub fn sk_to_pk(sk: &[u8; SK_LEN]) -> Result<[u8; PK_LEN], Error> {
    let mut pk = [0u8; PK_LEN];
    // SAFETY: sk and pk are sized buffers.
    let rc = unsafe { bls12_381_sk_to_pk(sk.as_ptr(), pk.as_mut_ptr()) };
    rc_to_result(rc).map(|()| pk)
}

/// Sign `msg` with the 32-byte secret key. Output is the 96-byte compressed
/// G2 signature.
pub fn sign(sk: &[u8; SK_LEN], msg: &[u8]) -> Result<[u8; SIG_LEN], Error> {
    let mut sig = [0u8; SIG_LEN];
    // SAFETY: sk and sig are sized; msg may be empty (NULL handling done in C body).
    let rc = unsafe {
        bls12_381_sign(
            sk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
        )
    };
    rc_to_result(rc).map(|()| sig)
}

/// Verify the 96-byte compressed signature against the 48-byte compressed
/// pubkey and msg. Performs subgroup checks on both points.
pub fn verify(pk: &[u8; PK_LEN], msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), Error> {
    // SAFETY: pk and sig are sized; msg may be empty.
    let rc = unsafe {
        bls12_381_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr())
    };
    rc_to_result(rc)
}

/// Aggregate `n = pks.len() / PK_LEN` compressed pubkeys into one. Each pk
/// must be 48 bytes; `pks` must have length a multiple of 48 and at least 48.
pub fn aggregate_pubkeys(pks: &[u8]) -> Result<[u8; PK_LEN], Error> {
    if pks.is_empty() || pks.len() % PK_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = pks.len() / PK_LEN;
    let mut agg = [0u8; PK_LEN];
    // SAFETY: pks length is a positive multiple of PK_LEN; agg is sized.
    let rc = unsafe { bls12_381_aggregate_pubkeys(pks.as_ptr(), n, agg.as_mut_ptr()) };
    rc_to_result(rc).map(|()| agg)
}

/// Aggregate `n = sigs.len() / SIG_LEN` compressed signatures into one.
pub fn aggregate_sigs(sigs: &[u8]) -> Result<[u8; SIG_LEN], Error> {
    if sigs.is_empty() || sigs.len() % SIG_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = sigs.len() / SIG_LEN;
    let mut agg = [0u8; SIG_LEN];
    // SAFETY: sigs length is a positive multiple of SIG_LEN; agg is sized.
    let rc = unsafe { bls12_381_aggregate_sigs(sigs.as_ptr(), n, agg.as_mut_ptr()) };
    rc_to_result(rc).map(|()| agg)
}

/// FastAggregateVerify: `n` pubkeys all signed the same `msg`. `pks` must
/// be a concatenation of `n * PK_LEN` bytes.
pub fn fast_aggregate_verify(
    pks: &[u8],
    msg: &[u8],
    agg_sig: &[u8; SIG_LEN],
) -> Result<(), Error> {
    if pks.is_empty() || pks.len() % PK_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = pks.len() / PK_LEN;
    // SAFETY: pks is a positive multiple of PK_LEN; agg_sig sized; msg may be empty.
    let rc = unsafe {
        bls12_381_fast_aggregate_verify(
            pks.as_ptr(),
            n,
            msg.as_ptr(),
            msg.len(),
            agg_sig.as_ptr(),
        )
    };
    rc_to_result(rc)
}

/// AggregateVerify with distinct messages per pubkey. `pks` is `n * PK_LEN`.
/// `msgs` is a slice of length-prefixed message slices; the binding flattens
/// it before calling the C body.
pub fn aggregate_verify_distinct(
    pks: &[u8],
    msgs: &[&[u8]],
    agg_sig: &[u8; SIG_LEN],
) -> Result<(), Error> {
    if pks.is_empty() || pks.len() % PK_LEN != 0 {
        return Err(Error::BadInput);
    }
    let n = pks.len() / PK_LEN;
    if n != msgs.len() {
        return Err(Error::BadInput);
    }
    let mut flat = Vec::with_capacity(msgs.iter().map(|m| m.len()).sum());
    let mut lens = Vec::with_capacity(n);
    for m in msgs {
        flat.extend_from_slice(m);
        lens.push(m.len());
    }
    // SAFETY: pks/agg_sig sized; flat/lens length-matches n; allow empty msgs.
    let rc = unsafe {
        bls12_381_aggregate_verify_distinct(
            pks.as_ptr(),
            n,
            flat.as_ptr(),
            lens.as_ptr(),
            agg_sig.as_ptr(),
        )
    };
    rc_to_result(rc)
}
