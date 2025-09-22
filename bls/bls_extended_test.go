package bls

import (
	"bytes"
	"testing"
)

func TestNewSecretKeyExtended(t *testing.T) {
	// Test multiple key generation
	for i := 0; i < 10; i++ {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate secret key: %v", err)
		}
		if sk == nil {
			t.Fatal("Generated secret key is nil")
		}
		if sk.sk == nil {
			t.Fatal("Internal secret key is nil")
		}
		
		// Verify keys are different
		sk2, err := NewSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate second secret key: %v", err)
		}
		
		bytes1 := SecretKeyToBytes(sk)
		bytes2 := SecretKeyToBytes(sk2)
		if bytes.Equal(bytes1, bytes2) {
			t.Fatal("Generated keys should be different")
		}
	}
}

func TestSecretKeyBytes(t *testing.T) {
	// Test with valid secret key
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	
	// Convert to bytes
	skBytes := SecretKeyToBytes(sk)
	if len(skBytes) == 0 {
		t.Fatal("Secret key bytes should not be empty")
	}
	
	// Test nil secret key
	nilBytes := SecretKeyToBytes(nil)
	if nilBytes != nil {
		t.Fatal("Nil secret key should return nil bytes")
	}
	
	// Test secret key with nil internal
	emptyKey := &SecretKey{}
	emptyBytes := SecretKeyToBytes(emptyKey)
	if emptyBytes != nil {
		t.Fatal("Secret key with nil internal should return nil bytes")
	}
	
	// Round-trip test
	sk2, err := SecretKeyFromBytes(skBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize secret key: %v", err)
	}
	
	skBytes2 := SecretKeyToBytes(sk2)
	if !bytes.Equal(skBytes, skBytes2) {
		t.Fatal("Round-trip secret key bytes should match")
	}
}

func TestSecretKeyFromBytesErrors(t *testing.T) {
	// Test with invalid bytes
	invalidBytes := make([]byte, 10) // Wrong size
	_, err := SecretKeyFromBytes(invalidBytes)
	if err == nil {
		t.Fatal("Should fail with invalid bytes")
	}
	
	// Test with nil bytes
	_, err = SecretKeyFromBytes(nil)
	if err == nil {
		t.Fatal("Should fail with nil bytes")
	}
	
	// Test with empty bytes
	_, err = SecretKeyFromBytes([]byte{})
	if err == nil {
		t.Fatal("Should fail with empty bytes")
	}
}

func TestPublicKeyOperations(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	
	// Get public key
	pk := sk.PublicKey()
	if pk == nil {
		t.Fatal("Public key should not be nil")
	}
	if pk.pk == nil {
		t.Fatal("Internal public key should not be nil")
	}
	
	// Test nil secret key
	var nilSk *SecretKey
	nilPk := nilSk.PublicKey()
	if nilPk != nil {
		t.Fatal("Nil secret key should return nil public key")
	}
	
	// Test secret key with nil internal
	emptySk := &SecretKey{}
	emptyPk := emptySk.PublicKey()
	if emptyPk != nil {
		t.Fatal("Empty secret key should return nil public key")
	}
}

func TestPublicKeyBytes(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	
	pk := sk.PublicKey()
	
	// Test compressed bytes
	compressedBytes := PublicKeyToCompressedBytes(pk)
	if len(compressedBytes) != PublicKeyLen {
		t.Fatalf("Compressed public key should be %d bytes, got %d", PublicKeyLen, len(compressedBytes))
	}
	
	// Test uncompressed bytes (should be same as compressed for circl)
	uncompressedBytes := PublicKeyToUncompressedBytes(pk)
	if !bytes.Equal(compressedBytes, uncompressedBytes) {
		t.Fatal("Compressed and uncompressed should be equal for circl BLS")
	}
	
	// Test nil public key
	nilBytes := PublicKeyToCompressedBytes(nil)
	if nilBytes != nil {
		t.Fatal("Nil public key should return nil bytes")
	}
	
	// Test public key with nil internal
	emptyPk := &PublicKey{}
	emptyBytes := PublicKeyToCompressedBytes(emptyPk)
	if emptyBytes != nil {
		t.Fatal("Empty public key should return nil bytes")
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	
	pk := sk.PublicKey()
	pkBytes := PublicKeyToCompressedBytes(pk)
	
	// Test valid deserialization
	pk2, err := PublicKeyFromCompressedBytes(pkBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}
	
	pkBytes2 := PublicKeyToCompressedBytes(pk2)
	if !bytes.Equal(pkBytes, pkBytes2) {
		t.Fatal("Round-trip public key bytes should match")
	}
	
	// Test from valid uncompressed bytes
	pk3 := PublicKeyFromValidUncompressedBytes(pkBytes)
	if pk3 == nil {
		t.Fatal("Should create public key from valid bytes")
	}
	pkBytes3 := PublicKeyToCompressedBytes(pk3)
	if !bytes.Equal(pkBytes, pkBytes3) {
		t.Fatal("Public key from valid bytes should match")
	}
}

func TestPublicKeyFromBytesErrors(t *testing.T) {
	// Test with wrong size
	invalidBytes := make([]byte, 10)
	_, err := PublicKeyFromCompressedBytes(invalidBytes)
	if err == nil {
		t.Fatal("Should fail with wrong size bytes")
	}
	
	// Test with nil
	_, err = PublicKeyFromCompressedBytes(nil)
	if err == nil {
		t.Fatal("Should fail with nil bytes")
	}
	
	// Test with invalid point (all zeros)
	zeroBytes := make([]byte, PublicKeyLen)
	_, err = PublicKeyFromCompressedBytes(zeroBytes)
	if err == nil {
		t.Fatal("Should fail with invalid point")
	}
}

func TestSignAndVerify(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	
	pk := sk.PublicKey()
	msg := []byte("test message")
	
	// Sign message
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	if sig == nil {
		t.Fatal("Signature should not be nil")
	}
	
	// Verify signature
	valid := Verify(pk, sig, msg)
	if !valid {
		t.Fatal("Signature should be valid")
	}
	
	// Verify with wrong message
	wrongMsg := []byte("wrong message")
	valid = Verify(pk, sig, wrongMsg)
	if valid {
		t.Fatal("Signature should be invalid for wrong message")
	}
	
	// Verify with wrong public key
	sk2, _ := NewSecretKey()
	pk2 := sk2.PublicKey()
	valid = Verify(pk2, sig, msg)
	if valid {
		t.Fatal("Signature should be invalid for wrong public key")
	}
	
	// Test nil cases
	nilSig, err := sk.Sign(nil)
	if err != nil {
		t.Fatalf("Failed to sign nil message: %v", err)
	}
	if nilSig == nil {
		t.Fatal("Should handle nil message")
	}
	
	var nilSk *SecretKey
	nilSig2, err := nilSk.Sign(msg)
	if err == nil {
		t.Fatal("Nil secret key should return error")
	}
	if nilSig2 != nil {
		t.Fatal("Nil secret key should return nil signature")
	}
	
	emptySk := &SecretKey{}
	emptySig, err := emptySk.Sign(msg)
	if err == nil {
		t.Fatal("Empty secret key should return error")
	}
	if emptySig != nil {
		t.Fatal("Empty secret key should return nil signature")
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	sk, _ := NewSecretKey()
	pk := sk.PublicKey()
	msg := []byte("test")
	sig, _ := sk.Sign(msg)
	
	// Test nil public key
	valid := Verify(nil, sig, msg)
	if valid {
		t.Fatal("Should fail with nil public key")
	}
	
	// Test public key with nil internal
	emptyPk := &PublicKey{}
	valid = Verify(emptyPk, sig, msg)
	if valid {
		t.Fatal("Should fail with empty public key")
	}
	
	// Test nil signature
	valid = Verify(pk, nil, msg)
	if valid {
		t.Fatal("Should fail with nil signature")
	}
}

func TestProofOfPossession(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}
	
	pk := sk.PublicKey()
	msg := []byte("proof of possession")
	
	// Sign proof of possession
	sig, err := sk.SignProofOfPossession(msg)
	if err != nil {
		t.Fatalf("Failed to sign PoP: %v", err)
	}
	if sig == nil {
		t.Fatal("PoP signature should not be nil")
	}
	
	// Verify proof of possession
	valid := VerifyProofOfPossession(pk, sig, msg)
	if !valid {
		t.Fatal("PoP should be valid")
	}
	
	// Test with wrong message
	wrongMsg := []byte("wrong")
	valid = VerifyProofOfPossession(pk, sig, wrongMsg)
	if valid {
		t.Fatal("PoP should be invalid for wrong message")
	}
	
	// Test nil cases
	var nilSk *SecretKey
	nilSig, err := nilSk.SignProofOfPossession(msg)
	if err == nil {
		t.Fatal("Nil secret key should return error")
	}
	if nilSig != nil {
		t.Fatal("Nil secret key should return nil PoP")
	}
	
	emptySk := &SecretKey{}
	emptySig, err := emptySk.SignProofOfPossession(msg)
	if err == nil {
		t.Fatal("Empty secret key should return error")
	}
	if emptySig != nil {
		t.Fatal("Empty secret key should return nil PoP")
	}
}

func TestSignatureBytes(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	msg := []byte("test")
	sig, _ := sk.Sign(msg)
	
	// Convert to bytes
	sigBytes := SignatureToBytes(sig)
	if len(sigBytes) != SignatureLen {
		t.Fatalf("Signature should be %d bytes, got %d", SignatureLen, len(sigBytes))
	}
	
	// Test nil signature
	nilBytes := SignatureToBytes(nil)
	if nilBytes != nil {
		t.Fatal("Nil signature should return nil bytes")
	}
	
	// Round-trip test
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}
	
	sigBytes2 := SignatureToBytes(sig2)
	if !bytes.Equal(sigBytes, sigBytes2) {
		t.Fatal("Round-trip signature bytes should match")
	}
}

func TestSignatureFromBytesErrors(t *testing.T) {
	// Test wrong size
	invalidBytes := make([]byte, 10)
	_, err := SignatureFromBytes(invalidBytes)
	if err == nil {
		t.Fatal("Should fail with wrong size")
	}
	
	// Test all zeros (invalid signature)
	zeroBytes := make([]byte, SignatureLen)
	_, err = SignatureFromBytes(zeroBytes)
	if err == nil {
		t.Fatal("Should fail with all zero bytes")
	}
	
	// Test nil
	_, err = SignatureFromBytes(nil)
	if err == nil {
		t.Fatal("Should fail with nil bytes")
	}
}

func TestAggregatePublicKeysEdgeCases(t *testing.T) {
	// Test empty slice
	_, err := AggregatePublicKeys([]*PublicKey{})
	if err == nil {
		t.Fatal("Should fail with empty slice")
	}
	
	// Test with nil public key in slice
	sk1, _ := NewSecretKey()
	pk1 := sk1.PublicKey()
	
	_, err = AggregatePublicKeys([]*PublicKey{pk1, nil})
	if err == nil {
		t.Fatal("Should fail with nil public key in slice")
	}
	
	// Test with public key with nil internal
	emptyPk := &PublicKey{}
	_, err = AggregatePublicKeys([]*PublicKey{pk1, emptyPk})
	if err == nil {
		t.Fatal("Should fail with empty public key in slice")
	}
}

func TestAggregateSignaturesEdgeCases(t *testing.T) {
	// Test empty slice
	_, err := AggregateSignatures([]*Signature{})
	if err == nil {
		t.Fatal("Should fail with empty slice")
	}
	
	// Test with nil signature in slice
	sk1, _ := NewSecretKey()
	msg := []byte("test")
	sig1, _ := sk1.Sign(msg)
	
	_, err = AggregateSignatures([]*Signature{sig1, nil})
	if err == nil {
		t.Fatal("Should fail with nil signature in slice")
	}
}

func TestMultipleAggregation(t *testing.T) {
	// Create multiple keys
	numKeys := 5
	sks := make([]*SecretKey, numKeys)
	pks := make([]*PublicKey, numKeys)
	sigs := make([]*Signature, numKeys)
	
	msg := []byte("aggregate test message")
	
	for i := 0; i < numKeys; i++ {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		sks[i] = sk
		pks[i] = sk.PublicKey()
		sigs[i], _ = sk.Sign(msg)
	}
	
	// Aggregate public keys
	aggPk, err := AggregatePublicKeys(pks)
	if err != nil {
		t.Fatalf("Failed to aggregate public keys: %v", err)
	}
	if aggPk == nil {
		t.Fatal("Aggregated public key should not be nil")
	}
	
	// Aggregate signatures
	aggSig, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("Failed to aggregate signatures: %v", err)
	}
	if aggSig == nil {
		t.Fatal("Aggregated signature should not be nil")
	}
	
	// Verify aggregated signature
	valid := Verify(aggPk, aggSig, msg)
	if !valid {
		t.Fatal("Aggregated signature should be valid")
	}
}

func BenchmarkKeyGenerationExtended(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewSecretKey()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignExtended(b *testing.B) {
	sk, _ := NewSecretKey()
	msg := []byte("benchmark message")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(msg)
	}
}

func BenchmarkVerifyExtended(b *testing.B) {
	sk, _ := NewSecretKey()
	pk := sk.PublicKey()
	msg := []byte("benchmark message")
	sig, _ := sk.Sign(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(pk, sig, msg)
	}
}

func BenchmarkAggregatePublicKeysExtended(b *testing.B) {
	numKeys := 10
	pks := make([]*PublicKey, numKeys)
	
	for i := 0; i < numKeys; i++ {
		sk, _ := NewSecretKey()
		pks[i] = sk.PublicKey()
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AggregatePublicKeys(pks)
	}
}

func BenchmarkAggregateSignaturesExtended(b *testing.B) {
	numSigs := 10
	sigs := make([]*Signature, numSigs)
	msg := []byte("benchmark")
	
	for i := 0; i < numSigs; i++ {
		sk, _ := NewSecretKey()
		sigs[i], _ = sk.Sign(msg)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AggregateSignatures(sigs)
	}
}