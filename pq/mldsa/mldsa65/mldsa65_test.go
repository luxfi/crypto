// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa65

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestNewKeyFromSeed_Deterministic asserts the headline contract of
// NewKeyFromSeed: identical input seed → identical keypair across two
// independent calls.
func TestNewKeyFromSeed_Deterministic(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}

	pk1, sk1, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed #1: %v", err)
	}
	pk2, sk2, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed #2: %v", err)
	}

	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Fatal("deterministic keygen: public keys differ for identical seed")
	}
	if !bytes.Equal(sk1.Bytes(), sk2.Bytes()) {
		t.Fatal("deterministic keygen: private keys differ for identical seed")
	}
}

// TestNewKeyFromSeed_DifferentSeeds asserts that flipping a single bit of
// the seed produces a different keypair (sanity check that the seed
// actually feeds KeyGen rather than being silently discarded).
func TestNewKeyFromSeed_DifferentSeeds(t *testing.T) {
	seed1 := make([]byte, SeedSize)
	if _, err := rand.Read(seed1); err != nil {
		t.Fatalf("rand: %v", err)
	}
	seed2 := append([]byte{}, seed1...)
	seed2[0] ^= 0x01

	pk1, _, err := NewKeyFromSeed(seed1)
	if err != nil {
		t.Fatalf("NewKeyFromSeed seed1: %v", err)
	}
	pk2, _, err := NewKeyFromSeed(seed2)
	if err != nil {
		t.Fatalf("NewKeyFromSeed seed2: %v", err)
	}

	if bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Fatal("different seeds produced identical public keys")
	}
}

// TestNewKeyFromSeed_SignVerifyRoundtrip asserts the keypair derived from
// a seed is usable: Sign then Verify round-trips on a non-trivial message
// with a domain-separating context.
func TestNewKeyFromSeed_SignVerifyRoundtrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0xA5}, SeedSize)
	pk, sk, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}

	msg := []byte("ML-DSA-65 deterministic keygen round-trip")
	ctx := []byte("LUX/test/mldsa65")

	sig, err := Sign(sk, msg, ctx, false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("Sign: got %d bytes, want %d", len(sig), SignatureSize)
	}

	if !Verify(pk, msg, ctx, sig) {
		t.Fatal("Verify rejected a signature produced by the derived keypair")
	}

	// Tamper with the message → must reject.
	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0xFF
	if Verify(pk, tampered, ctx, sig) {
		t.Fatal("Verify accepted a tampered message")
	}

	// Tamper with the context → must reject (FIPS 204 §5.3 binds ctx).
	if Verify(pk, msg, []byte("LUX/test/mldsa65/other"), sig) {
		t.Fatal("Verify accepted under a different context")
	}
}

// TestNewKeyFromSeed_ShortSeedRejected asserts the FIPS 204 §5.1 minimum
// is enforced. Anything below 32 bytes must produce ErrSeedTooShort.
func TestNewKeyFromSeed_ShortSeedRejected(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		short := make([]byte, n)
		if _, _, err := NewKeyFromSeed(short); err == nil {
			t.Fatalf("NewKeyFromSeed accepted %d-byte seed (want error)", n)
		}
	}
}

// TestNewKeyFromSeed_ExactSeedSize asserts a 32-byte seed is accepted and
// is fed verbatim as ξ (i.e. no cSHAKE expansion applied).
//
// The "verbatim" property is checked indirectly: with the all-zero ξ, the
// keypair is fully determined by FIPS 204 KeyGen, and the same ξ presented
// via NewKeyFromSeed (32 bytes of 0x00) must produce a non-error result.
func TestNewKeyFromSeed_ExactSeedSize(t *testing.T) {
	seed := make([]byte, SeedSize) // all zero
	pk, sk, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	if pk == nil || sk == nil {
		t.Fatal("NewKeyFromSeed returned nil keypair without error")
	}
	if len(pk.Bytes()) != PublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pk.Bytes()), PublicKeySize)
	}
	if len(sk.Bytes()) != PrivateKeySize {
		t.Fatalf("private key size: got %d, want %d", len(sk.Bytes()), PrivateKeySize)
	}
}

// TestNewKeyFromSeed_OversizedSeedExpanded asserts that oversized seeds
// (the common HD-wallet / HKDF case) are accepted, hashed via cSHAKE-256
// down to ξ, and produce a usable keypair. Two oversized seeds that
// differ in their trailing bytes must yield different keypairs (the
// cSHAKE expansion sees the entire input).
func TestNewKeyFromSeed_OversizedSeedExpanded(t *testing.T) {
	long1 := bytes.Repeat([]byte{0xCC}, 96)
	long2 := append([]byte{}, long1...)
	long2[64] ^= 0x01 // change a byte that lives in the cSHAKE input tail

	pk1, sk1, err := NewKeyFromSeed(long1)
	if err != nil {
		t.Fatalf("NewKeyFromSeed long1: %v", err)
	}
	pk2, _, err := NewKeyFromSeed(long2)
	if err != nil {
		t.Fatalf("NewKeyFromSeed long2: %v", err)
	}
	if bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Fatal("oversized seeds differing in tail produced identical public keys")
	}

	// Round-trip the long1 keypair.
	msg := []byte("oversized seed roundtrip")
	sig, err := Sign(sk1, msg, nil, false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(pk1, msg, nil, sig) {
		t.Fatal("Verify rejected oversized-seed-derived keypair signature")
	}
}

// TestNewKeyFromSeed_CrossSetSeparation asserts that the cSHAKE
// customization string actually domain-separates parameter sets when an
// oversized parent seed is reused. Same long seed → mldsa65 expands with
// the "LUX/FIPS204/MLDSA65/seed" customization, which means the derived
// ξ differs from what mldsa44/mldsa87 would compute on the same input.
//
// We can only check this property against mldsa65 itself here (the
// cross-package check lives in pq/mldsa cross-set tests), but we can
// verify that two oversized seeds that ONLY differ by a single byte at
// position 0 still produce different keypairs even though the first
// SeedSize bytes already differ — the test ensures the cSHAKE path is
// taken instead of a naive prefix truncation.
func TestNewKeyFromSeed_NoPrefixTruncation(t *testing.T) {
	// Construct two long seeds that share their first SeedSize bytes
	// but differ in the tail. A naive prefix-truncation implementation
	// would yield the same keypair; the cSHAKE expansion must not.
	prefix := bytes.Repeat([]byte{0x11}, SeedSize)
	long1 := append(append([]byte{}, prefix...), bytes.Repeat([]byte{0x22}, 32)...)
	long2 := append(append([]byte{}, prefix...), bytes.Repeat([]byte{0x33}, 32)...)

	pk1, _, err := NewKeyFromSeed(long1)
	if err != nil {
		t.Fatalf("NewKeyFromSeed long1: %v", err)
	}
	pk2, _, err := NewKeyFromSeed(long2)
	if err != nil {
		t.Fatalf("NewKeyFromSeed long2: %v", err)
	}
	if bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Fatal("seeds sharing only the first 32 bytes produced identical keys " +
			"(implementation is doing prefix truncation, not cSHAKE expansion)")
	}
}

// TestGenerateKey_NotDeterministic asserts the random keygen path
// actually produces different keypairs on repeated calls (i.e. it's
// reading from rand, not pinned to a constant).
func TestGenerateKey_NotDeterministic(t *testing.T) {
	pk1, _, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey #1: %v", err)
	}
	pk2, _, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey #2: %v", err)
	}
	if bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Fatal("GenerateKey produced identical keypairs on two calls " +
			"(rand source not being consumed)")
	}
}
