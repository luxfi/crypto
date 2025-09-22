// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewSecretKey(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	if sk == nil {
		t.Fatal("Secret key is nil")
	}
	if sk.sk == nil {
		t.Fatal("Internal secret key is nil")
	}
}

func TestSecretKeyToBytes(t *testing.T) {
	// Test nil secret key
	if data := SecretKeyToBytes(nil); data != nil {
		t.Fatal("Expected nil for nil secret key")
	}

	// Test nil internal key
	sk := &SecretKey{sk: nil}
	if data := SecretKeyToBytes(sk); data != nil {
		t.Fatal("Expected nil for nil internal key")
	}

	// Test valid secret key
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	data := SecretKeyToBytes(sk)
	if len(data) != SecretKeyLen {
		t.Fatalf("Expected %d bytes, got %d", SecretKeyLen, len(data))
	}
}

func TestSecretKeyFromBytes(t *testing.T) {
	// Generate a secret key
	sk1, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	// Convert to bytes
	skBytes := SecretKeyToBytes(sk1)

	// Convert back from bytes
	sk2, err := SecretKeyFromBytes(skBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize secret key: %v", err)
	}

	// Check they produce the same public key
	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()

	bytes1 := PublicKeyToCompressedBytes(pk1)
	bytes2 := PublicKeyToCompressedBytes(pk2)

	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("Public keys don't match after serialization")
	}

	// Test invalid bytes
	invalidBytes := make([]byte, 10) // Wrong size
	_, err = SecretKeyFromBytes(invalidBytes)
	if err == nil {
		t.Fatal("Expected error for invalid bytes")
	}
}

func TestPublicKey(t *testing.T) {
	// Test nil secret key
	var sk *SecretKey
	if pk := sk.PublicKey(); pk != nil {
		t.Fatal("Expected nil public key from nil secret key")
	}

	// Test nil internal key
	sk = &SecretKey{sk: nil}
	if pk := sk.PublicKey(); pk != nil {
		t.Fatal("Expected nil public key from nil internal key")
	}

	// Test valid secret key
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk := sk.PublicKey()
	if pk == nil {
		t.Fatal("Public key is nil")
	}
	if pk.pk == nil {
		t.Fatal("Internal public key is nil")
	}
}

func TestSign(t *testing.T) {
	msg := []byte("test message")

	// Test nil secret key
	var sk *SecretKey
	if sig, err := sk.Sign(msg); err == nil || sig != nil {
		t.Fatal("Expected error and nil signature from nil secret key")
	}

	// Test nil internal key
	sk = &SecretKey{sk: nil}
	if sig, err := sk.Sign(msg); err == nil || sig != nil {
		t.Fatal("Expected error and nil signature from nil internal key")
	}

	// Test valid signing
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	if sig == nil {
		t.Fatal("Signature is nil")
	}
}

func TestSignProofOfPossession(t *testing.T) {
	msg := []byte("proof of possession")

	// Test nil secret key
	var sk *SecretKey
	if sig, err := sk.SignProofOfPossession(msg); err == nil || sig != nil {
		t.Fatal("Expected error and nil signature from nil secret key")
	}

	// Test nil internal key
	sk = &SecretKey{sk: nil}
	if sig, err := sk.SignProofOfPossession(msg); err == nil || sig != nil {
		t.Fatal("Expected error and nil signature from nil internal key")
	}

	// Test valid signing
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	sig, err := sk.SignProofOfPossession(msg)
	if err != nil {
		t.Fatalf("Failed to sign proof of possession: %v", err)
	}
	if sig == nil {
		t.Fatal("Signature is nil")
	}
}

func TestPublicKeyToCompressedBytes(t *testing.T) {
	// Test nil public key
	if data := PublicKeyToCompressedBytes(nil); data != nil {
		t.Fatal("Expected nil for nil public key")
	}

	// Test nil internal key
	pk := &PublicKey{pk: nil}
	if data := PublicKeyToCompressedBytes(pk); data != nil {
		t.Fatal("Expected nil for nil internal key")
	}

	// Test valid public key
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk = sk.PublicKey()
	pkBytes := PublicKeyToCompressedBytes(pk)
	if len(pkBytes) != PublicKeyLen {
		t.Fatalf("Expected %d bytes, got %d", PublicKeyLen, len(pkBytes))
	}
}

func TestPublicKeyFromCompressedBytes(t *testing.T) {
	// Generate a key pair
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk1 := sk.PublicKey()
	pkBytes := PublicKeyToCompressedBytes(pk1)

	// Deserialize
	pk2, err := PublicKeyFromCompressedBytes(pkBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}

	// Check they're the same
	bytes1 := PublicKeyToCompressedBytes(pk1)
	bytes2 := PublicKeyToCompressedBytes(pk2)
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("Public keys don't match after serialization")
	}

	// Test invalid bytes
	invalidBytes := make([]byte, 10) // Wrong size
	_, err = PublicKeyFromCompressedBytes(invalidBytes)
	if err == nil {
		t.Fatal("Expected error for invalid bytes")
	}
}

func TestPublicKeyToUncompressedBytes(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk := sk.PublicKey()
	compressedBytes := PublicKeyToCompressedBytes(pk)
	uncompressedBytes := PublicKeyToUncompressedBytes(pk)

	// For circl/bls, compressed and uncompressed should be the same
	if !bytes.Equal(compressedBytes, uncompressedBytes) {
		t.Fatal("Compressed and uncompressed bytes should be the same")
	}
}

func TestPublicKeyFromValidUncompressedBytes(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk1 := sk.PublicKey()
	pkBytes := PublicKeyToUncompressedBytes(pk1)

	pk2 := PublicKeyFromValidUncompressedBytes(pkBytes)
	if pk2 == nil {
		t.Fatal("Failed to create public key from valid bytes")
	}

	// Check they're the same
	bytes1 := PublicKeyToCompressedBytes(pk1)
	bytes2 := PublicKeyToCompressedBytes(pk2)
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("Public keys don't match")
	}
}

func TestVerify(t *testing.T) {
	msg := []byte("test message")

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk := sk.PublicKey()
	sig, _ := sk.Sign(msg)

	// Test valid signature
	if !Verify(pk, sig, msg) {
		t.Fatal("Failed to verify valid signature")
	}

	// Test wrong message
	wrongMsg := []byte("wrong message")
	if Verify(pk, sig, wrongMsg) {
		t.Fatal("Verified signature with wrong message")
	}

	// Test wrong public key
	sk2, _ := NewSecretKey()
	pk2 := sk2.PublicKey()
	if Verify(pk2, sig, msg) {
		t.Fatal("Verified signature with wrong public key")
	}

	// Test nil public key
	if Verify(nil, sig, msg) {
		t.Fatal("Verified signature with nil public key")
	}

	// Test nil signature
	if Verify(pk, nil, msg) {
		t.Fatal("Verified nil signature")
	}

	// Test nil internal public key
	pkNil := &PublicKey{pk: nil}
	if Verify(pkNil, sig, msg) {
		t.Fatal("Verified signature with nil internal public key")
	}
}

func TestVerifyProofOfPossession(t *testing.T) {
	msg := []byte("proof of possession")

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	pk := sk.PublicKey()
	sig, _ := sk.SignProofOfPossession(msg)

	// Test valid proof
	if !VerifyProofOfPossession(pk, sig, msg) {
		t.Fatal("Failed to verify valid proof of possession")
	}

	// Test wrong message
	wrongMsg := []byte("wrong message")
	if VerifyProofOfPossession(pk, sig, wrongMsg) {
		t.Fatal("Verified proof with wrong message")
	}
}

func TestSignatureToBytes(t *testing.T) {
	// Test nil signature
	if data := SignatureToBytes(nil); data != nil {
		t.Fatal("Expected nil for nil signature")
	}

	// Test valid signature
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	msg := []byte("test message")
	sig, _ := sk.Sign(msg)
	sigBytes := SignatureToBytes(sig)
	if len(sigBytes) != SignatureLen {
		t.Fatalf("Expected %d bytes, got %d", SignatureLen, len(sigBytes))
	}
}

func TestSignatureFromBytes(t *testing.T) {
	// Generate a signature
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	msg := []byte("test message")
	sig1, _ := sk.Sign(msg)
	sigBytes := SignatureToBytes(sig1)

	// Deserialize
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}

	// Check they're the same
	bytes1 := SignatureToBytes(sig1)
	bytes2 := SignatureToBytes(sig2)
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("Signatures don't match after serialization")
	}

	// Test invalid size
	invalidBytes := make([]byte, 10)
	_, err = SignatureFromBytes(invalidBytes)
	if err == nil {
		t.Fatal("Expected error for invalid size")
	}

	// Test all zeros
	zeroBytes := make([]byte, SignatureLen)
	_, err = SignatureFromBytes(zeroBytes)
	if err == nil {
		t.Fatal("Expected error for all zero signature")
	}
}

func TestAggregatePublicKeys(t *testing.T) {
	// Test empty slice
	_, err := AggregatePublicKeys([]*PublicKey{})
	if err != ErrNoPublicKeys {
		t.Fatal("Expected ErrNoPublicKeys for empty slice")
	}

	// Generate keys
	sk1, _ := NewSecretKey()
	sk2, _ := NewSecretKey()
	sk3, _ := NewSecretKey()

	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()
	pk3 := sk3.PublicKey()

	// Test aggregation
	aggPk, err := AggregatePublicKeys([]*PublicKey{pk1, pk2, pk3})
	if err != nil {
		t.Fatalf("Failed to aggregate public keys: %v", err)
	}
	if aggPk == nil {
		t.Fatal("Aggregated public key is nil")
	}

	// Test with nil key
	_, err = AggregatePublicKeys([]*PublicKey{pk1, nil, pk3})
	if err == nil {
		t.Fatal("Expected error for nil public key in slice")
	}

	// Test with nil internal key
	pkNil := &PublicKey{pk: nil}
	_, err = AggregatePublicKeys([]*PublicKey{pk1, pkNil, pk3})
	if err == nil {
		t.Fatal("Expected error for nil internal public key in slice")
	}
}

func TestAggregateSignatures(t *testing.T) {
	// Test empty slice
	_, err := AggregateSignatures([]*Signature{})
	if err != ErrNoSignatures {
		t.Fatal("Expected ErrNoSignatures for empty slice")
	}

	// Generate signatures
	msg := []byte("test message")
	sk1, _ := NewSecretKey()
	sk2, _ := NewSecretKey()
	sk3, _ := NewSecretKey()

	sig1, _ := sk1.Sign(msg)
	sig2, _ := sk2.Sign(msg)
	sig3, _ := sk3.Sign(msg)

	// Test aggregation
	aggSig, err := AggregateSignatures([]*Signature{sig1, sig2, sig3})
	if err != nil {
		t.Fatalf("Failed to aggregate signatures: %v", err)
	}
	if aggSig == nil {
		t.Fatal("Aggregated signature is nil")
	}

	// Test with nil signature
	_, err = AggregateSignatures([]*Signature{sig1, nil, sig3})
	if err == nil {
		t.Fatal("Expected error for nil signature in slice")
	}
}

func TestMultiSignature(t *testing.T) {
	// Generate multiple key pairs
	msg := []byte("multi-signature test")
	n := 5
	secretKeys := make([]*SecretKey, n)
	publicKeys := make([]*PublicKey, n)
	signatures := make([]*Signature, n)

	for i := 0; i < n; i++ {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate secret key %d: %v", i, err)
		}
		secretKeys[i] = sk
		publicKeys[i] = sk.PublicKey()
		signatures[i], _ = sk.Sign(msg)
	}

	// Aggregate public keys and signatures
	aggPk, err := AggregatePublicKeys(publicKeys)
	if err != nil {
		t.Fatalf("Failed to aggregate public keys: %v", err)
	}

	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		t.Fatalf("Failed to aggregate signatures: %v", err)
	}

	// Verify aggregated signature
	if !Verify(aggPk, aggSig, msg) {
		t.Fatal("Failed to verify aggregated signature")
	}

	// Test with wrong message
	wrongMsg := []byte("wrong message")
	if Verify(aggPk, aggSig, wrongMsg) {
		t.Fatal("Verified aggregated signature with wrong message")
	}
}

func TestEdgeCases(t *testing.T) {
	// Test with empty message
	emptyMsg := []byte{}
	sk, _ := NewSecretKey()
	pk := sk.PublicKey()
	sig, _ := sk.Sign(emptyMsg)
	if !Verify(pk, sig, emptyMsg) {
		t.Fatal("Failed to verify signature on empty message")
	}

	// Test with very long message
	longMsg := make([]byte, 10000)
	rand.Read(longMsg)
	sig, _ = sk.Sign(longMsg)
	if !Verify(pk, sig, longMsg) {
		t.Fatal("Failed to verify signature on long message")
	}
}

func BenchmarkNewSecretKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewSecretKey()
	}
}

func BenchmarkSign(b *testing.B) {
	sk, _ := NewSecretKey()
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	sk, _ := NewSecretKey()
	pk := sk.PublicKey()
	msg := []byte("benchmark message")
	sig, _ := sk.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(pk, sig, msg)
	}
}

func BenchmarkAggregatePublicKeys(b *testing.B) {
	n := 10
	pks := make([]*PublicKey, n)
	for i := 0; i < n; i++ {
		sk, _ := NewSecretKey()
		pks[i] = sk.PublicKey()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AggregatePublicKeys(pks)
	}
}

func BenchmarkAggregateSignatures(b *testing.B) {
	n := 10
	msg := []byte("benchmark message")
	sigs := make([]*Signature, n)
	for i := 0; i < n; i++ {
		sk, _ := NewSecretKey()
		sigs[i], _ = sk.Sign(msg)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AggregateSignatures(sigs)
	}
}