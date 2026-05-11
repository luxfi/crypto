// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mldsa is the canonical Lux entry point for ML-DSA
// (Module-Lattice-Based Digital Signature Algorithm, FIPS 204).
//
// Each FIPS 204 parameter set lives in its own subpackage. Choose the
// security level at compile time by importing the right one:
//
//	github.com/luxfi/crypto/pq/mldsa/mldsa44  // NIST Level 2
//	github.com/luxfi/crypto/pq/mldsa/mldsa65  // NIST Level 3 (recommended)
//	github.com/luxfi/crypto/pq/mldsa/mldsa87  // NIST Level 5
//
// Each subpackage exposes:
//
//	GenerateKey(rand io.Reader)        — random keygen
//	NewKeyFromSeed(seed []byte)        — deterministic keygen (FIPS 204 §5.1)
//	Sign(sk, msg, ctx) ([]byte, error) — domain-separated signing
//	Verify(pk, msg, ctx, sig) bool     — domain-separated verification
//
// Deterministic keygen is the entry point HD-wallet derivation, validator
// identity provisioning, and DKG round-seed paths use to materialize a
// keypair from a child seed produced by a cSHAKE-derived chain. The
// per-parameter-set constant SeedSize is exactly the FIPS 204 §5.1 ξ
// length (32 bytes).
package mldsa
