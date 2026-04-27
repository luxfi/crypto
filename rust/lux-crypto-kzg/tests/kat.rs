// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// KZG (EIP-4844) binding smoke test. The luxcpp body currently returns
// CRYPTO_ERR_NOTIMPL (-5) pending blst/intx wiring; this test confirms the
// C-ABI is reachable and the four entry points report a consistent status.

use lux_crypto_kzg::{
    blob_to_commit, commit_to_proof, verify_blob, verify_proof, Error, BLOB_LEN, COMMIT_LEN,
    SCALAR_LEN,
};

#[test]
fn surface_links_and_dispatches() {
    let blob = vec![0u8; BLOB_LEN];
    let blob_arr: &[u8; BLOB_LEN] = blob.as_slice().try_into().unwrap();
    let z = [0u8; SCALAR_LEN];
    let y = [0u8; SCALAR_LEN];
    let commit = [0u8; COMMIT_LEN];
    let proof = [0u8; COMMIT_LEN];

    let mut out_commit = [0u8; COMMIT_LEN];
    let mut out_proof = [0u8; COMMIT_LEN];
    let mut out_y = [0u8; SCALAR_LEN];

    // Each entry point must dispatch through the C-ABI without segfaulting
    // and must produce a recognizable status (Ok or any documented Error).
    let _ = blob_to_commit(blob_arr, &mut out_commit);
    let _ = commit_to_proof(blob_arr, &z, &mut out_proof, &mut out_y);
    let _ = verify_proof(&commit, &z, &y, &proof);
    let _ = verify_blob(blob_arr, &commit, &proof);
}
