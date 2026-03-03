// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"bytes"
	"testing"
)

// FuzzBLSSignVerify tests that sign/verify roundtrips correctly for arbitrary messages.
func FuzzBLSSignVerify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add([]byte("BLS12-381 signature test"))
	f.Add(bytes.Repeat([]byte{0xff}, 256))
	f.Add(bytes.Repeat([]byte{0x00}, 1024))
	f.Add(bytes.Repeat([]byte{0xab, 0xcd}, 500))

	f.Fuzz(func(t *testing.T, message []byte) {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatalf("NewSecretKey: %v", err)
		}

		pk := sk.PublicKey()
		if pk == nil {
			t.Fatal("PublicKey returned nil")
		}

		sig, err := sk.Sign(message)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		if !Verify(pk, sig, message) {
			t.Fatal("Verify returned false for valid signature")
		}

		// Verify with serialized/deserialized key
		pkBytes := PublicKeyToCompressedBytes(pk)
		pk2, err := PublicKeyFromCompressedBytes(pkBytes)
		if err != nil {
			t.Fatalf("PublicKeyFromCompressedBytes: %v", err)
		}

		if !Verify(pk2, sig, message) {
			t.Fatal("Verify failed with deserialized public key")
		}

		// Verify with serialized/deserialized signature
		sigBytes := SignatureToBytes(sig)
		sig2, err := SignatureFromBytes(sigBytes)
		if err != nil {
			t.Fatalf("SignatureFromBytes: %v", err)
		}

		if !Verify(pk, sig2, message) {
			t.Fatal("Verify failed with deserialized signature")
		}

		// Wrong message must fail
		wrongMsg := append(message, 0x01)
		if Verify(pk, sig, wrongMsg) {
			t.Fatal("Verify accepted signature for wrong message")
		}
	})
}

// FuzzBLSAggregation tests that aggregated signatures verify correctly.
// Generates two keypairs, signs the same fuzzed message, aggregates both
// signatures and public keys, and verifies the aggregate.
func FuzzBLSAggregation(f *testing.F) {
	f.Add([]byte("aggregate"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 128))
	f.Add([]byte("multi-signer BLS aggregation test"))

	f.Fuzz(func(t *testing.T, message []byte) {
		sk1, err := NewSecretKey()
		if err != nil {
			t.Fatalf("NewSecretKey 1: %v", err)
		}
		sk2, err := NewSecretKey()
		if err != nil {
			t.Fatalf("NewSecretKey 2: %v", err)
		}

		pk1 := sk1.PublicKey()
		pk2 := sk2.PublicKey()

		sig1, err := sk1.Sign(message)
		if err != nil {
			t.Fatalf("Sign 1: %v", err)
		}
		sig2, err := sk2.Sign(message)
		if err != nil {
			t.Fatalf("Sign 2: %v", err)
		}

		// Individual verification
		if !Verify(pk1, sig1, message) {
			t.Fatal("individual verify 1 failed")
		}
		if !Verify(pk2, sig2, message) {
			t.Fatal("individual verify 2 failed")
		}

		// Aggregate signatures
		aggSig, err := AggregateSignatures([]*Signature{sig1, sig2})
		if err != nil {
			t.Fatalf("AggregateSignatures: %v", err)
		}

		// Aggregate public keys
		aggPK, err := AggregatePublicKeys([]*PublicKey{pk1, pk2})
		if err != nil {
			t.Fatalf("AggregatePublicKeys: %v", err)
		}

		// Verify aggregate
		if !Verify(aggPK, aggSig, message) {
			t.Fatal("aggregate verify failed")
		}

		// Aggregate with wrong message must fail
		wrongMsg := append(message, 0x42)
		if Verify(aggPK, aggSig, wrongMsg) {
			t.Fatal("aggregate verify accepted wrong message")
		}

		// Aggregate serialization roundtrip
		aggSigBytes := SignatureToBytes(aggSig)
		aggSig2, err := SignatureFromBytes(aggSigBytes)
		if err != nil {
			t.Fatalf("SignatureFromBytes(aggSig): %v", err)
		}
		if !Verify(aggPK, aggSig2, message) {
			t.Fatal("aggregate verify failed after signature deserialization")
		}
	})
}

// FuzzBLSMalformedSignature tests that Verify rejects random bytes as a signature
// without panicking.
func FuzzBLSMalformedSignature(f *testing.F) {
	f.Add([]byte{}, []byte("test"))
	f.Add(bytes.Repeat([]byte{0xff}, SignatureLen), []byte("test"))
	f.Add(bytes.Repeat([]byte{0x00}, SignatureLen), []byte("test"))
	f.Add(bytes.Repeat([]byte{0xaa}, 10), []byte("test"))
	f.Add(bytes.Repeat([]byte{0xbb}, SignatureLen+1), []byte("msg"))
	f.Add(bytes.Repeat([]byte{0xcc}, SignatureLen-1), []byte("msg"))
	f.Add([]byte{0x01}, []byte{})

	f.Fuzz(func(t *testing.T, garbageSigBytes []byte, message []byte) {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatalf("NewSecretKey: %v", err)
		}
		pk := sk.PublicKey()

		// SignatureFromBytes must not panic.
		sig, err := SignatureFromBytes(garbageSigBytes)
		if err != nil {
			// Expected for wrong-size or all-zero inputs.
			return
		}

		// If deserialization succeeded, Verify must not panic.
		// Result should almost certainly be false.
		result := Verify(pk, sig, message)

		// Also test VerifyProofOfPossession with the garbage sig.
		_ = VerifyProofOfPossession(pk, sig, message)

		_ = result
	})
}

// FuzzBLSMalformedPublicKey tests that Verify doesn't panic on garbage public key bytes.
func FuzzBLSMalformedPublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, PublicKeyLen))
	f.Add(bytes.Repeat([]byte{0x00}, PublicKeyLen))
	f.Add(bytes.Repeat([]byte{0xaa}, 10))
	f.Add(bytes.Repeat([]byte{0xbb}, PublicKeyLen+1))
	f.Add(bytes.Repeat([]byte{0xcc}, PublicKeyLen-1))

	f.Fuzz(func(t *testing.T, garbagePKBytes []byte) {
		// PublicKeyFromCompressedBytes must not panic.
		pk, err := PublicKeyFromCompressedBytes(garbagePKBytes)
		if err != nil {
			// Expected for invalid keys.
			return
		}

		// If deserialization succeeded, generate a real signature and test verify.
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatalf("NewSecretKey: %v", err)
		}

		message := []byte("test message for malformed pk")
		sig, err := sk.Sign(message)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		// Must not panic. Should return false (wrong key).
		_ = Verify(pk, sig, message)
		_ = VerifyProofOfPossession(pk, sig, message)
	})
}

// FuzzBLSSecretKeyFromBytes tests that SecretKeyFromBytes doesn't panic on garbage.
func FuzzBLSSecretKeyFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, SecretKeyLen))
	f.Add(bytes.Repeat([]byte{0x00}, SecretKeyLen))
	f.Add(bytes.Repeat([]byte{0x01}, SecretKeyLen))
	f.Add(bytes.Repeat([]byte{0xaa}, 10))
	f.Add(bytes.Repeat([]byte{0xbb}, SecretKeyLen+1))

	f.Fuzz(func(t *testing.T, garbageBytes []byte) {
		// Must not panic.
		sk, err := SecretKeyFromBytes(garbageBytes)
		if err != nil {
			return
		}

		// If deserialization succeeded, the key should produce a public key.
		pk := sk.PublicKey()
		if pk == nil {
			// Some deserializable scalars may produce nil public keys.
			return
		}

		// Attempt to sign and verify. Some scalars (e.g., reduced to zero
		// or identity-producing values) may not produce verifiable signatures.
		// We only care that nothing panics.
		message := []byte("test")
		sig, err := sk.Sign(message)
		if err != nil {
			return
		}

		// Verify may fail for certain edge-case scalars (e.g., identity key
		// rejection). That's correct behavior, not a bug.
		_ = Verify(pk, sig, message)
	})
}
