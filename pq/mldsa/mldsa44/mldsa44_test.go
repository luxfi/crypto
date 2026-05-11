// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa44

import (
	"bytes"
	"crypto/rand"
	"testing"
)

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

func TestNewKeyFromSeed_SignVerifyRoundtrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0xA5}, SeedSize)
	pk, sk, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}

	msg := []byte("ML-DSA-44 deterministic keygen round-trip")
	ctx := []byte("LUX/test/mldsa44")

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

	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0xFF
	if Verify(pk, tampered, ctx, sig) {
		t.Fatal("Verify accepted a tampered message")
	}
	if Verify(pk, msg, []byte("LUX/test/mldsa44/other"), sig) {
		t.Fatal("Verify accepted under a different context")
	}
}

func TestNewKeyFromSeed_ShortSeedRejected(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		short := make([]byte, n)
		if _, _, err := NewKeyFromSeed(short); err == nil {
			t.Fatalf("NewKeyFromSeed accepted %d-byte seed (want error)", n)
		}
	}
}

func TestNewKeyFromSeed_ExactSeedSize(t *testing.T) {
	seed := make([]byte, SeedSize)
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

func TestNewKeyFromSeed_OversizedSeedExpanded(t *testing.T) {
	long1 := bytes.Repeat([]byte{0xCC}, 96)
	long2 := append([]byte{}, long1...)
	long2[64] ^= 0x01

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

	msg := []byte("oversized seed roundtrip")
	sig, err := Sign(sk1, msg, nil, false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(pk1, msg, nil, sig) {
		t.Fatal("Verify rejected oversized-seed-derived keypair signature")
	}
}

func TestNewKeyFromSeed_NoPrefixTruncation(t *testing.T) {
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
