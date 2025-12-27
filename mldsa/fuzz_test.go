// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// FuzzMLDSASignVerify tests that sign/verify roundtrips correctly for arbitrary messages.
// Generates a fresh keypair per mode, signs the fuzzed message, and verifies it.
func FuzzMLDSASignVerify(f *testing.F) {
	// Seed corpus: empty, short, medium, and binary messages
	f.Add([]byte{}, uint8(0))
	f.Add([]byte("hello world"), uint8(0))
	f.Add([]byte("hello world"), uint8(1))
	f.Add([]byte("hello world"), uint8(2))
	f.Add(bytes.Repeat([]byte{0xff}, 256), uint8(0))
	f.Add(bytes.Repeat([]byte{0x00}, 1024), uint8(1))
	f.Add([]byte("ML-DSA post-quantum digital signature test"), uint8(2))

	// Pre-generate one keypair per mode for seed corpus validation
	for _, mode := range []Mode{MLDSA44, MLDSA65, MLDSA87} {
		sk, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			f.Fatalf("keygen mode %d: %v", mode, err)
		}
		msg := []byte("seed message")
		sig, err := sk.Sign(rand.Reader, msg, nil)
		if err != nil {
			f.Fatalf("sign mode %d: %v", mode, err)
		}
		f.Add(msg, uint8(mode))
		_ = sig // just used to validate keygen/sign works in seed phase
	}

	f.Fuzz(func(t *testing.T, message []byte, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		sk, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", mode, err)
		}

		sig, err := sk.Sign(rand.Reader, message, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		expectedSigSize := GetSignatureSize(mode)
		if len(sig) != expectedSigSize {
			t.Fatalf("signature size = %d, want %d", len(sig), expectedSigSize)
		}

		if !sk.PublicKey.VerifySignature(message, sig) {
			t.Fatal("VerifySignature returned false for valid signature")
		}

		// Verify with deserialized public key
		pkBytes := sk.PublicKey.Bytes()
		pk2, err := PublicKeyFromBytes(pkBytes, mode)
		if err != nil {
			t.Fatalf("PublicKeyFromBytes: %v", err)
		}
		if !pk2.VerifySignature(message, sig) {
			t.Fatal("deserialized public key failed to verify")
		}
	})
}

// FuzzMLDSAMalformedSignature tests that Verify rejects random bytes as a signature
// without panicking.
func FuzzMLDSAMalformedSignature(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 96), uint8(0))
	f.Add(bytes.Repeat([]byte{0xaa}, 2420), uint8(0))   // MLDSA44 sig size
	f.Add(bytes.Repeat([]byte{0xbb}, 3309), uint8(1))   // MLDSA65 sig size
	f.Add(bytes.Repeat([]byte{0xcc}, 4627), uint8(2))   // MLDSA87 sig size
	f.Add(bytes.Repeat([]byte{0x00}, 4627), uint8(2))
	f.Add([]byte{0x01}, uint8(1))
	f.Add(bytes.Repeat([]byte{0xde, 0xad}, 2000), uint8(0))

	f.Fuzz(func(t *testing.T, garbageSig []byte, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		sk, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", mode, err)
		}

		message := []byte("fixed message for malformed sig test")

		// Must not panic. Should return false for garbage.
		result := sk.PublicKey.VerifySignature(message, garbageSig)

		// A random byte slice matching the exact signature size has negligible
		// probability of being a valid signature, but we cannot assert false
		// for the exact-size case without knowing the internals. For wrong-size
		// inputs, verification must always fail.
		expectedSize := GetSignatureSize(mode)
		if len(garbageSig) != expectedSize && result {
			t.Fatal("VerifySignature returned true for wrong-size signature")
		}
	})
}

// FuzzMLDSAMalformedPublicKey tests that Verify doesn't panic when given garbage
// public key bytes. Exercises both PublicKeyFromBytes and direct VerifySignature
// on a PublicKey constructed from arbitrary bytes.
func FuzzMLDSAMalformedPublicKey(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 48), uint8(0))
	f.Add(bytes.Repeat([]byte{0x00}, 1312), uint8(0))   // MLDSA44 pk size
	f.Add(bytes.Repeat([]byte{0xaa}, 1952), uint8(1))   // MLDSA65 pk size
	f.Add(bytes.Repeat([]byte{0xbb}, 2592), uint8(2))   // MLDSA87 pk size
	f.Add(bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 500), uint8(1))

	f.Fuzz(func(t *testing.T, garbagePK []byte, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		// PublicKeyFromBytes should either return an error or a usable key.
		// It must never panic.
		pk, err := PublicKeyFromBytes(garbagePK, mode)
		if err != nil {
			// Expected for most garbage inputs.
			return
		}

		// If deserialization succeeded, verify must not panic.
		// Generate a real signature from a real key to test verify path.
		sk, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		message := []byte("test message")
		sig, err := sk.Sign(rand.Reader, message, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		// Verify with the garbage-derived public key. Must not panic.
		// Result should be false (different key), but we only care about no-panic.
		_ = pk.VerifySignature(message, sig)

		// Also test with a PublicKey built from raw bytes (bypassing validation).
		// This exercises the VerifySignature path with potentially invalid internal state.
		rawPK := &PublicKey{
			mode:      mode,
			publicKey: garbagePK,
		}
		_ = rawPK.VerifySignature(message, sig)
	})
}
