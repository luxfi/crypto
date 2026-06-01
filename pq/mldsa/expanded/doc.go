// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package expanded implements the EIP-8051 expanded-public-key form
// for ML-DSA, where the matrix A (FIPS 204 §3.6.3 ExpandA) is
// precomputed and carried alongside the compact (ρ ‖ t1) public key.
//
// The expansion is deterministic and reproducible: given the compact
// public key bytes, ExpandedA is fully determined by the 32-byte ρ
// prefix and the parameter set (K, L). Re-expanding always yields the
// same byte sequence — this is what makes the form usable as a cache
// rather than a separate trust root.
//
// Layout for an ML-DSA-65 expanded key:
//
//	Compact   : 1952 bytes — FIPS 204 §6.4 public-key encoding
//	ExpandedA : K × L × N × 23 bits, byte-packed
//	            = 6 × 5 × 256 × 23 / 8 = 22,080 bytes
//
// The 23-bit packing matches the coefficient bound q − 1 < 2²³
// (FIPS 204 §3.4: q = 2²³ − 2¹³ + 1 = 8 380 417). EIP-8051 quotes
// "~20,512 bytes" for the same security level using a slightly
// different in-memory layout; our serialization is canonical for the
// luxfi/crypto stack and round-trips losslessly. The same packing
// rule applies to ML-DSA-44 (K=4, L=4 → 11,776 bytes) and ML-DSA-87
// (K=8, L=7 → 41,216 bytes); see the per-parameter Size constants.
//
// API surface:
//
//	Expand(compact) (*PublicKey, error)   — derive ExpandedA from ρ
//	Compact(*PublicKey) []byte            — drop ExpandedA, keep ρ ‖ t1
//	Verify(*PublicKey, msg, ctx, sig) bool — variance-checked verify
//
// Verify cross-checks the carried ExpandedA against a fresh expansion
// (so a tampered cache cannot make a bad signature accept) and then
// delegates to the canonical FIPS 204 verifier in
// crypto/pq/mldsa/mldsa65. The cross-check is a byte comparison on
// the freshly-derived expansion and is independent of the upstream
// CIRCL verifier's own internal ExpandA call.
//
// This package is FIPS 204 conformant in the sense that Verify
// accepts iff the canonical FIPS 204 verifier accepts; it does not
// modify the wire signature format and it is not the variant
// described in crypto/pq/mldsa/ethdilithium_compat.
package expanded
