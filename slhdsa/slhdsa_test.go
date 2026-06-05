// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSLHDSA_SignVerify_SHA2_128s(t *testing.T) {
	// Generate a key
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get public key
	pk := sk.PublicKey.Bytes()
	expectedSize := GetPublicKeySize(SHA2_128s)
	if len(pk) != expectedSize {
		t.Fatalf("Invalid public key size: got %d, want %d", len(pk), expectedSize)
	}

	// Sign a message
	message := []byte("test message for SLH-DSA-SHA2-128s")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	expectedSigSize := GetSignatureSize(SHA2_128s)
	if len(signature) != expectedSigSize {
		t.Fatalf("Invalid signature size: got %d, want %d", len(signature), expectedSigSize)
	}

	// Verify signature
	if !sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Signature verification failed")
	}
}

func TestSLHDSA_SignVerify_SHAKE_128s(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHAKE_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("test message for SLH-DSA-SHAKE-128s")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if !sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Signature verification failed")
	}
}

func TestSLHDSA_SignVerify_SHA2_256s(t *testing.T) {
	// SHA-2-256s is the slowest production mode (~1.5s sign without
	// -race, ~10s with). The matching SHA2_256f variant gives
	// equivalent FIPS-205 compliance coverage at ~50ms; gate the slow
	// "s" variant under -short.
	if testing.Short() {
		t.Skip("skipping SLH-DSA-SHA2-256s slow variant under -short")
	}

	sk, err := GenerateKey(rand.Reader, SHA2_256s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("test message for SLH-DSA-SHA2-256s")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	expectedSigSize := GetSignatureSize(SHA2_256s)
	if len(signature) != expectedSigSize {
		t.Fatalf("Invalid signature size: got %d, want %d", len(signature), expectedSigSize)
	}

	if !sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Signature verification failed")
	}
}

func TestSLHDSA_InvalidSignature(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("test message")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Modify signature
	signature[0] ^= 0xFF

	// Verification should fail
	if sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Expected signature verification to fail")
	}
}

func TestSLHDSA_WrongMessage(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message1 := []byte("message 1")
	signature, err := sk.Sign(rand.Reader, message1, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	message2 := []byte("message 2")

	// Verification should fail with wrong message
	if sk.PublicKey.Verify(message2, signature, nil) {
		t.Fatal("Expected signature verification to fail with wrong message")
	}
}

func TestSLHDSA_EmptyMessage(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify empty message signature
	if !sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Empty message signature verification failed")
	}
}

func TestSLHDSA_LargeMessage(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a large message (10KB)
	message := make([]byte, 10240)
	for i := range message {
		message[i] = byte(i % 256)
	}

	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign large message: %v", err)
	}

	if !sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Large message signature verification failed")
	}
}

func TestSLHDSA_PrivateKeyFromBytes(t *testing.T) {
	// Generate a key
	sk1, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Serialize
	skBytes := sk1.Bytes()

	// Deserialize
	sk2, err := PrivateKeyFromBytes(SHA2_128s, skBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize private key: %v", err)
	}

	// Public keys should match
	pk1 := sk1.PublicKey.Bytes()
	pk2 := sk2.PublicKey.Bytes()

	if !bytes.Equal(pk1, pk2) {
		t.Fatal("Public keys should match after deserialization")
	}

	// Sign with sk2 and verify with sk1's public key
	message := []byte("test")
	signature, err := sk2.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if !sk1.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Signature verification failed after key deserialization")
	}
}

func TestSLHDSA_PublicKeyFromBytes(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Serialize public key
	pkBytes := sk.PublicKey.Bytes()

	// Deserialize
	pk, err := PublicKeyFromBytes(pkBytes, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}

	// Sign with original key
	message := []byte("test")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify with deserialized public key
	if !pk.Verify(message, signature, nil) {
		t.Fatal("Signature verification failed with deserialized public key")
	}
}

func TestSLHDSA_AllModes(t *testing.T) {
	// Test that all modes are supported.
	//
	// The "s" variants (small signature, deep WOTS+ chains) push sign
	// to ~1.5s without -race and ~10s under -race — aggregate ~6s/35s.
	// Under -short we keep a subset covering one (SHA-2, SHAKE) × one
	// (s, f) combination per level so the mode-mapping coverage stays
	// intact at a fraction of the cost.
	allModes := []Mode{
		SHA2_128s, SHAKE_128s, SHA2_128f, SHAKE_128f,
		SHA2_192s, SHAKE_192s, SHA2_192f, SHAKE_192f,
		SHA2_256s, SHAKE_256s, SHA2_256f, SHAKE_256f,
	}
	shortModes := []Mode{
		SHA2_128f, SHAKE_128f, // fast 128-bit variants
		SHA2_192f, SHAKE_192f, // fast 192-bit variants
		SHA2_256f, SHAKE_256f, // fast 256-bit variants
	}
	modes := allModes
	if testing.Short() {
		modes = shortModes
	}

	for _, mode := range modes {
		t.Run(modeToID(mode).String(), func(t *testing.T) {
			sk, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("Expected mode %d to be supported, got error: %v", mode, err)
			}
			if sk == nil {
				t.Fatalf("Expected non-nil key for mode %d", mode)
			}

			// Quick sign/verify test
			message := []byte("test")
			signature, err := sk.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			if !sk.PublicKey.Verify(message, signature, nil) {
				t.Fatal("Signature verification failed")
			}
		})
	}
}

func TestSLHDSA_InvalidMode(t *testing.T) {
	// Test invalid mode
	_, err := GenerateKey(rand.Reader, Mode(999))
	if err == nil {
		t.Fatal("Expected error for invalid mode 999")
	}
}

func TestSLHDSA_InvalidKeySize(t *testing.T) {
	// Too short
	data := make([]byte, 10)
	_, err := PrivateKeyFromBytes(SHA2_128s, data)
	if err == nil {
		t.Fatal("Expected error for invalid private key size")
	}

	// Invalid public key size
	data = make([]byte, 10)
	_, err = PublicKeyFromBytes(data, SHA2_128s)
	if err == nil {
		t.Fatal("Expected error for invalid public key size")
	}
}

func TestSLHDSA_GetPublicKeySize(t *testing.T) {
	tests := []struct {
		mode         Mode
		expectedSize int
	}{
		{SHA2_128s, 32},
		{SHAKE_128f, 32},
		{SHA2_192s, 48},
		{SHAKE_192f, 48},
		{SHA2_256s, 64},
		{SHAKE_256f, 64},
	}

	for _, tt := range tests {
		size := GetPublicKeySize(tt.mode)
		if size != tt.expectedSize {
			t.Fatalf("Mode %v: expected %d, got %d", tt.mode, tt.expectedSize, size)
		}
	}

	// Invalid mode
	size := GetPublicKeySize(Mode(999))
	if size != 0 {
		t.Fatalf("Expected 0 for invalid mode, got %d", size)
	}
}

func TestSLHDSA_GetSignatureSize(t *testing.T) {
	tests := []struct {
		mode         Mode
		expectedSize int
	}{
		{SHA2_128s, 7856},
		{SHAKE_128s, 7856},
		{SHA2_128f, 17088},
		{SHAKE_128f, 17088},
		{SHA2_192s, 16224},
		{SHAKE_192s, 16224},
		{SHA2_192f, 35664},
		{SHAKE_192f, 35664},
		{SHA2_256s, 29792},
		{SHAKE_256s, 29792},
		{SHA2_256f, 49856},
		{SHAKE_256f, 49856},
	}

	for _, tt := range tests {
		size := GetSignatureSize(tt.mode)
		if size != tt.expectedSize {
			t.Fatalf("Mode %v: expected %d, got %d", tt.mode, tt.expectedSize, size)
		}
	}

	// Invalid mode
	size := GetSignatureSize(Mode(999))
	if size != 0 {
		t.Fatalf("Expected 0 for invalid mode, got %d", size)
	}
}

func TestSLHDSA_DeterministicSigning(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("deterministic test")

	// Sign the same message twice
	sig1, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	sig2, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Signatures should be identical (deterministic signing)
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Expected deterministic signatures to be identical")
	}
}

func TestSLHDSA_Zeroize(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Copy key bytes before zeroize
	original := make([]byte, len(sk.Bytes()))
	copy(original, sk.Bytes())

	// Verify key material is non-zero
	allZero := true
	for _, b := range original {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("Key material should not be all zeros before Zeroize")
	}

	sk.Zeroize()

	// After zeroize, all bytes must be zero
	for i, b := range sk.Bytes() {
		if b != 0 {
			t.Fatalf("Byte %d not zeroed: 0x%02x", i, b)
		}
	}
}

func TestSLHDSA_Zeroize_FromBytes(t *testing.T) {
	sk1, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	skBytes := make([]byte, len(sk1.Bytes()))
	copy(skBytes, sk1.Bytes())

	sk2, err := PrivateKeyFromBytes(SHA2_128s, skBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	sk2.Zeroize()

	for i, b := range sk2.Bytes() {
		if b != 0 {
			t.Fatalf("Byte %d not zeroed: 0x%02x", i, b)
		}
	}
}

// Benchmark tests
func BenchmarkSLHDSA_Sign_SHA2_128s(b *testing.B) {
	sk, _ := GenerateKey(rand.Reader, SHA2_128s)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkSLHDSA_Verify_SHA2_128s(b *testing.B) {
	sk, _ := GenerateKey(rand.Reader, SHA2_128s)
	message := []byte("benchmark message")
	signature, _ := sk.Sign(rand.Reader, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.PublicKey.Verify(message, signature, nil)
	}
}

func BenchmarkSLHDSA_KeyGeneration_SHA2_128s(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(rand.Reader, SHA2_128s)
	}
}

func BenchmarkSLHDSA_Sign_SHA2_256s(b *testing.B) {
	sk, _ := GenerateKey(rand.Reader, SHA2_256s)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkSLHDSA_Verify_SHA2_256s(b *testing.B) {
	sk, _ := GenerateKey(rand.Reader, SHA2_256s)
	message := []byte("benchmark message")
	signature, _ := sk.Sign(rand.Reader, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.PublicKey.Verify(message, signature, nil)
	}
}
