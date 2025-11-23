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
	// Test that all modes are supported
	modes := []Mode{
		SHA2_128s, SHAKE_128s, SHA2_128f, SHAKE_128f,
		SHA2_192s, SHAKE_192s, SHA2_192f, SHAKE_192f,
		SHA2_256s, SHAKE_256s, SHA2_256f, SHAKE_256f,
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
