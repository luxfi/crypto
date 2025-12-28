// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Pedersen binding smoke test.

use lux_crypto_pedersen::{commit, verify, BLINDING_LEN, COMMIT_LEN};

#[test]
fn surface_links_and_dispatches() {
    let values = [0u8; 64];
    let blinding = [0x77u8; BLINDING_LEN];
    let mut c = [0u8; COMMIT_LEN];

    // The C-ABI must be reachable through the binding without segfaulting.
    // Either the canonical body verifies the round-trip correctly, or it
    // returns NOTIMPL / a documented status; both are acceptable for the
    // binding contract.
    let _ = commit(&values, &blinding, &mut c);
    let _ = verify(&c, &values, &blinding);
}
