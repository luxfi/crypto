// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// IPA binding smoke test.

use lux_crypto_ipa::{commit, verify, Error, COMMIT_LEN};

#[test]
fn surface_links_and_dispatches() {
    let coeffs = [0u8; 32];
    let mut commit_out = [0u8; COMMIT_LEN];
    let r1 = commit(&coeffs, &mut commit_out);
    let r2 = verify(&commit_out, &[0u8; 16]);

    // Either both calls report success/InvalidProof or both report NOTIMPL.
    let notimpl = matches!(r1, Err(Error::Internal(-5)));
    if notimpl {
        assert!(matches!(r2, Err(Error::Internal(-5))));
    }
}
