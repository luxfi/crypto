// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

func TestSLHDSA_SignVerify(t *testing.T) {
	// Generate a key
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	for i := range seed {
		seed[i] = byte(i)
	}

	sk, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	// Get public key
	pk := sk.PublicKey()
	expectedPKSize, _ := GetSizes(ModeSLH_DSA_128s)
	if len(pk) != expectedPKSize {
		t.Fatalf("Invalid public key size: got %d, want %d", len(pk), expectedPKSize)
	}

	// Sign a message
	message := []byte("test message for SLH-DSA-128s")
	signature := sk.Sign(message, nil)
	_, expectedSigSize := GetSizes(ModeSLH_DSA_128s)
	if len(signature) != expectedSigSize {
		t.Fatalf("Invalid signature size: got %d, want %d", len(signature), expectedSigSize)
	}

	// Verify signature
	if !Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Signature verification failed")
	}
}

func TestSLHDSA_InvalidSignature(t *testing.T) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	pk := sk.PublicKey()
	message := []byte("test message")
	signature := sk.Sign(message, nil)

	// Modify signature
	signature[0] ^= 0xFF

	// Verification should fail
	if Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Expected signature verification to fail")
	}
}

func TestSLHDSA_WrongMessage(t *testing.T) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	pk := sk.PublicKey()
	message1 := []byte("message 1")
	signature := sk.Sign(message1, nil)

	message2 := []byte("message 2")

	// Verification should fail with wrong message
	if Verify(ModeSLH_DSA_128s, pk, message2, signature) {
		t.Fatal("Expected signature verification to fail with wrong message")
	}
}

func TestSLHDSA_WithContext(t *testing.T) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	pk := sk.PublicKey()
	message := []byte("test message")
	context := []byte("test context")

	// Sign with context
	signature := sk.Sign(message, context)

	// Verify with context
	if !VerifyWithContext(ModeSLH_DSA_128s, pk, message, signature, context) {
		t.Fatal("Signature verification with context failed")
	}

	// Verify without context should fail
	if Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Expected verification without context to fail")
	}
}

func TestSLHDSA_EmptyMessage(t *testing.T) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	pk := sk.PublicKey()
	message := []byte("")
	signature := sk.Sign(message, nil)

	// Verify empty message signature
	if !Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Empty message signature verification failed")
	}
}

func TestSLHDSA_DeterministicSignatures(t *testing.T) {
	// Same seed should produce same key
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	for i := range seed {
		seed[i] = byte(i)
	}

	sk1, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key 1: %v", err)
	}

	sk2, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err != nil {
		t.Fatalf("Failed to create signing key 2: %v", err)
	}

	// Public keys should be identical
	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()

	if !bytes.Equal(pk1, pk2) {
		t.Fatal("Public keys should be identical for same seed")
	}
}

func TestSLHDSA_GenerateKey(t *testing.T) {
	sk, err := GenerateKey(ModeSLH_DSA_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pk := sk.PublicKey()
	expectedPKSize, _ := GetSizes(ModeSLH_DSA_128s)
	if len(pk) != expectedPKSize {
		t.Fatalf("Invalid public key size: got %d, want %d", len(pk), expectedPKSize)
	}

	// Test signing with generated key
	message := []byte("test")
	signature := sk.Sign(message, nil)

	if !Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Signature verification failed for generated key")
	}
}

func TestSLHDSA_InvalidMode(t *testing.T) {
	seed := make([]byte, 48)

	// Try unsupported mode (using invalid ID)
	_, err := NewSigningKey(slhdsa.ID(99), seed)
	if err == nil {
		t.Fatal("Expected error for unsupported mode")
	}

	_, err = GenerateKey(slhdsa.ID(99))
	if err == nil {
		t.Fatal("Expected error for unsupported mode")
	}
}

func TestSLHDSA_InvalidSeed(t *testing.T) {
	// Too short
	seed := make([]byte, 16)
	_, err := NewSigningKey(ModeSLH_DSA_128s, seed)
	if err == nil {
		t.Fatal("Expected error for invalid seed length")
	}

	// Too long
	seed = make([]byte, 128)
	_, err = NewSigningKey(ModeSLH_DSA_128s, seed)
	if err == nil {
		t.Fatal("Expected error for invalid seed length")
	}
}

func TestSLHDSA_InvalidPublicKey(t *testing.T) {
	message := []byte("test")
	_, sigSize := GetSizes(ModeSLH_DSA_128s)
	signature := make([]byte, sigSize)

	// Too short
	pk := make([]byte, 10)
	if Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Expected verification to fail with invalid public key size")
	}

	// Too long
	pk = make([]byte, 100)
	if Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Expected verification to fail with invalid public key size")
	}
}

func TestSLHDSA_InvalidSignatureSize(t *testing.T) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, _ := NewSigningKey(ModeSLH_DSA_128s, seed)
	pk := sk.PublicKey()
	message := []byte("test")

	// Too short
	signature := make([]byte, 100)
	if Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Expected verification to fail with invalid signature size")
	}

	// Too long
	signature = make([]byte, 10000)
	if Verify(ModeSLH_DSA_128s, pk, message, signature) {
		t.Fatal("Expected verification to fail with invalid signature size")
	}
}

// Benchmark tests
func BenchmarkSLHDSA_Sign(b *testing.B) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, _ := NewSigningKey(ModeSLH_DSA_128s, seed)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.Sign(message, nil)
	}
}

func BenchmarkSLHDSA_Verify(b *testing.B) {
	seed := make([]byte, GetSeedSize(ModeSLH_DSA_128s))
	sk, _ := NewSigningKey(ModeSLH_DSA_128s, seed)
	pk := sk.PublicKey()
	message := []byte("benchmark message")
	signature := sk.Sign(message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(ModeSLH_DSA_128s, pk, message, signature)
	}
}

func BenchmarkSLHDSA_KeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(ModeSLH_DSA_128s)
	}
}
