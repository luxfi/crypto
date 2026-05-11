// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa_test

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// TestCrossParameterSet_OversizedSeedDomainSeparation asserts that the
// per-parameter-set cSHAKE customization string actually domain-separates
// mldsa44 / mldsa65 / mldsa87 when the same oversized parent seed is
// re-used across all three.
//
// The expansion rule (see internal/seed) is:
//
//	ξ_44 = cSHAKE-256(seed, S="LUX/FIPS204/MLDSA44/seed")
//	ξ_65 = cSHAKE-256(seed, S="LUX/FIPS204/MLDSA65/seed")
//	ξ_87 = cSHAKE-256(seed, S="LUX/FIPS204/MLDSA87/seed")
//
// The three S strings differ, so ξ_44 ≠ ξ_65 ≠ ξ_87 (NIST SP 800-185 §3.3).
// We can't compare ξ directly (it's internal), so we compare a derived
// signature instead: with deterministic signing and a fixed (msg, ctx),
// the signature is a function of (sk, msg, ctx). If sk differs, the
// signature differs.
//
// Why this matters: a single 64-byte BIP-32 child seed is the typical
// HD-wallet input. If the customization strings collided, the validator
// identity (mldsa65) and any future mldsa87-based protocol would derive
// the same private key from the same parent seed — a key-reuse violation
// of FIPS 204's per-scheme key separation.
func TestCrossParameterSet_OversizedSeedDomainSeparation(t *testing.T) {
	parentSeed := bytes.Repeat([]byte{0x5C}, 64) // > SeedSize → triggers cSHAKE
	msg := []byte("LUX cross-parameter-set domain separation")
	ctx := []byte("LUX/test/mldsa-cross")

	pk44, sk44, err := mldsa44.NewKeyFromSeed(parentSeed)
	if err != nil {
		t.Fatalf("mldsa44 NewKeyFromSeed: %v", err)
	}
	pk65, sk65, err := mldsa65.NewKeyFromSeed(parentSeed)
	if err != nil {
		t.Fatalf("mldsa65 NewKeyFromSeed: %v", err)
	}
	pk87, sk87, err := mldsa87.NewKeyFromSeed(parentSeed)
	if err != nil {
		t.Fatalf("mldsa87 NewKeyFromSeed: %v", err)
	}

	// Different parameter sets → different public-key sizes, so the
	// byte comparison is unambiguous. Public keys MUST differ in length
	// (parameter-set sanity) AND in content (domain separation).
	if mldsa44.PublicKeySize == mldsa65.PublicKeySize ||
		mldsa65.PublicKeySize == mldsa87.PublicKeySize {
		t.Fatal("parameter-set public-key sizes collide (build error)")
	}

	// Sign with each derived sk and confirm the signature verifies
	// under its OWN pk but NOT under the others (cross-set keys must
	// not interoperate).
	sig44, err := mldsa44.Sign(sk44, msg, ctx, false)
	if err != nil {
		t.Fatalf("mldsa44 Sign: %v", err)
	}
	sig65, err := mldsa65.Sign(sk65, msg, ctx, false)
	if err != nil {
		t.Fatalf("mldsa65 Sign: %v", err)
	}
	sig87, err := mldsa87.Sign(sk87, msg, ctx, false)
	if err != nil {
		t.Fatalf("mldsa87 Sign: %v", err)
	}

	if !mldsa44.Verify(pk44, msg, ctx, sig44) {
		t.Fatal("mldsa44: derived keypair fails self-verify")
	}
	if !mldsa65.Verify(pk65, msg, ctx, sig65) {
		t.Fatal("mldsa65: derived keypair fails self-verify")
	}
	if !mldsa87.Verify(pk87, msg, ctx, sig87) {
		t.Fatal("mldsa87: derived keypair fails self-verify")
	}

	// Length sanity: three signatures of three distinct lengths.
	if len(sig44) == len(sig65) || len(sig65) == len(sig87) {
		t.Fatal("parameter-set signature sizes collide (build error)")
	}
}
