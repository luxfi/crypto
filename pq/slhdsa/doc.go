// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package slhdsa is the canonical Lux entry point for SLH-DSA
// (Stateless Hash-Based Digital Signature Algorithm, FIPS 205).
//
// The package is structured along two axes:
//
//  1. The full Mode catalogue (twelve parameter sets per FIPS 205 §10)
//     lives in the github.com/luxfi/crypto/slhdsa subpackage. That is the
//     canonical entry point for keygen, sign, verify, and KAT-replay.
//
//  2. The GPU/CPU-batched fast path lives in
//     github.com/luxfi/crypto/pq/slhdsa/gpu. That package exposes the
//     FIPS 205 §10 parameter table and a SignBatch / VerifyBatch dispatch
//     that forwards into the canonical SignBatch / VerifyBatch with the
//     full GPU → goroutine-parallel → serial fallback ladder.
//
// Canonical parameter sets used by the Lux validator quorum:
//
//   - SLH-DSA-SHA2-192f  (NIST Level 3, "fast" / Magnetar recovery profile)
//   - SLH-DSA-SHA2-256f  (NIST Level 5, "fast" / high-value tier)
//
// FIPS 205 SignDeterministic has no per-call randomness, so all three
// dispatch tiers (GPU substrate, goroutine-parallel CPU, serial CPU)
// produce byte-identical signatures for any fixed (sk, msg). KAT-level
// equivalence is asserted in the gpu/ test suite and in the canonical
// slhdsa package's kat_test.go.
package slhdsa
