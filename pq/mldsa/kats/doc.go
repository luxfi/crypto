// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kats implements Known-Answer-Test (KAT) regression
// vectors for the FIPS 204 ML-DSA-44 / ML-DSA-65 / ML-DSA-87
// parameter sets as wrapped by crypto/pq/mldsa.
//
// Each parameter set has a slice of pinned Vector records of the
// form (Seed, Msg, Ctx, PublicKey, PrivateKey, Signature). At test
// time, every vector is re-derived from its Seed via
// mldsaXX.NewKeyFromSeed and mldsaXX.Sign(..., randomized=false),
// then compared byte-for-byte against the pinned record. A
// mismatch is a regression in the deterministic-keygen or
// deterministic-sign path.
//
// # Origin
//
// FIPS 204 was finalized August 2024. NIST's ACVP-Server publishes
// a JSON test-vector battery (keyGen / sigGen / sigVer) that CIRCL,
// the upstream we delegate to, already runs against in its own
// test suite — those vectors are not redistributed here.
//
// The vectors in this package are SYNTHETIC: they are produced
// deterministically by the same code paths under test, pinned by
// hand, and serve as a regression tripwire — the test asserts that
// the bytes do not move silently between releases. Replace these
// vectors with official NIST CAVS .rsp files when those are
// published in a form suitable for direct ingestion.
//
// # Discipline
//
// The generator (kats/internal/gen) writes the same Go source the
// tests load. Running it twice produces byte-identical output, so a
// `go run ./pq/mldsa/kats/internal/gen` invocation that produces a
// diff is itself the regression signal. The Makefile target
// `make gen_kats` exposes this.
package kats
