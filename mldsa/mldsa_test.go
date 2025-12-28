// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMLDSA_SignVerify(t *testing.T) {
	// Generate a key
	sk, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get public key
	pk := sk.PublicKey.Bytes()
	if len(pk) != MLDSA65PublicKeySize {
		t.Fatalf("Invalid public key size: got %d, want %d", len(pk), MLDSA65PublicKeySize)
	}

	// Sign a message
	message := []byte("test message for ML-DSA-65")
	signature, err := sk.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	if len(signature) != MLDSA65SignatureSize {
		t.Fatalf("Invalid signature size: got %d, want %d", len(signature), MLDSA65SignatureSize)
	}

	// Verify signature
	if !sk.PublicKey.Verify(message, signature, nil) {
		t.Fatal("Signature verification failed")
	}
}

func TestMLDSA_InvalidSignature(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, MLDSA65)
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

func TestMLDSA_WrongMessage(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, MLDSA65)
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

func TestMLDSA_EmptyMessage(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, MLDSA65)
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

func TestMLDSA_LargeMessage(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, MLDSA65)
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

func TestMLDSA_PrivateKeyFromBytes(t *testing.T) {
	// Generate a key
	sk1, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Serialize
	skBytes := sk1.Bytes()
	if len(skBytes) != MLDSA65PrivateKeySize {
		t.Fatalf("Invalid private key size: got %d, want %d", len(skBytes), MLDSA65PrivateKeySize)
	}

	// Deserialize
	sk2, err := PrivateKeyFromBytes(MLDSA65, skBytes)
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

func TestMLDSA_PublicKeyFromBytes(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Serialize public key
	pkBytes := sk.PublicKey.Bytes()

	// Deserialize
	pk, err := PublicKeyFromBytes(pkBytes, MLDSA65)
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

func TestMLDSA_InvalidMode(t *testing.T) {
	// Test that all three modes are supported
	for _, mode := range []Mode{MLDSA44, MLDSA65, MLDSA87} {
		sk, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("Expected mode %d to be supported, got error: %v", mode, err)
		}
		if sk == nil {
			t.Fatalf("Expected non-nil key for mode %d", mode)
		}
	}

	// Test invalid mode
	_, err := GenerateKey(rand.Reader, Mode(999))
	if err == nil {
		t.Fatal("Expected error for invalid mode 999")
	}
}

func TestMLDSA_InvalidKeySize(t *testing.T) {
	// Too short
	data := make([]byte, 100)
	_, err := PrivateKeyFromBytes(MLDSA65, data)
	if err == nil {
		t.Fatal("Expected error for invalid private key size")
	}

	// Too long
	data = make([]byte, 5000)
	_, err = PrivateKeyFromBytes(MLDSA65, data)
	if err == nil {
		t.Fatal("Expected error for invalid private key size")
	}

	// Invalid public key size
	data = make([]byte, 100)
	_, err = PublicKeyFromBytes(data, MLDSA65)
	if err == nil {
		t.Fatal("Expected error for invalid public key size")
	}
}

func TestMLDSA_GetPublicKeySize(t *testing.T) {
	size := GetPublicKeySize(MLDSA65)
	if size != MLDSA65PublicKeySize {
		t.Fatalf("Expected %d, got %d", MLDSA65PublicKeySize, size)
	}

	size = GetPublicKeySize(MLDSA44)
	if size != MLDSA44PublicKeySize {
		t.Fatalf("Expected %d, got %d", MLDSA44PublicKeySize, size)
	}

	size = GetPublicKeySize(MLDSA87)
	if size != MLDSA87PublicKeySize {
		t.Fatalf("Expected %d, got %d", MLDSA87PublicKeySize, size)
	}

	size = GetPublicKeySize(Mode(999))
	if size != 0 {
		t.Fatalf("Expected 0 for invalid mode, got %d", size)
	}
}

func TestMLDSA_GetSignatureSize(t *testing.T) {
	size := GetSignatureSize(MLDSA65)
	if size != MLDSA65SignatureSize {
		t.Fatalf("Expected %d, got %d", MLDSA65SignatureSize, size)
	}

	size = GetSignatureSize(MLDSA44)
	if size != MLDSA44SignatureSize {
		t.Fatalf("Expected %d, got %d", MLDSA44SignatureSize, size)
	}

	size = GetSignatureSize(MLDSA87)
	if size != MLDSA87SignatureSize {
		t.Fatalf("Expected %d, got %d", MLDSA87SignatureSize, size)
	}

	size = GetSignatureSize(Mode(999))
	if size != 0 {
		t.Fatalf("Expected 0 for invalid mode, got %d", size)
	}
}

// Benchmark tests
func BenchmarkMLDSA_Sign(b *testing.B) {
	sk, _ := GenerateKey(rand.Reader, MLDSA65)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkMLDSA_Verify(b *testing.B) {
	sk, _ := GenerateKey(rand.Reader, MLDSA65)
	message := []byte("benchmark message")
	signature, _ := sk.Sign(rand.Reader, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.PublicKey.Verify(message, signature, nil)
	}
}

func BenchmarkMLDSA_KeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(rand.Reader, MLDSA65)
	}
}

func TestMLDSA_Zeroize(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, MLDSA65)
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

func TestMLDSA_Zeroize_FromBytes(t *testing.T) {
	sk1, err := GenerateKey(rand.Reader, MLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	skBytes := make([]byte, len(sk1.Bytes()))
	copy(skBytes, sk1.Bytes())

	sk2, err := PrivateKeyFromBytes(MLDSA65, skBytes)
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
