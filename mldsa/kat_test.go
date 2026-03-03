// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// KAT (Known Answer Test) vectors for ML-DSA-65 (FIPS 204, NIST Level 3).
//
// These are deterministic test vectors generated from a fixed seed using
// circl's NewKeyFromSeed. The seed, public key prefix, signature prefix,
// and verification result are pinned to detect any change in the underlying
// implementation across library upgrades.

// katSeedHex is the 32-byte keygen seed (0x00..0x1f).
const katSeedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// katPKPrefixHex is the first 32 bytes of the expected public key.
const katPKPrefixHex = "48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27"

// katSigPrefixHex is the first 32 bytes of a deterministic (non-randomized) signature
// over the message "test message for KAT" with nil context.
const katSigPrefixHex = "315198eef238c57413cf89696a59e96ce7b3dcd7e1196f2883176eb690637533"

// katMessage is the message signed in the KAT.
var katMessage = []byte("test message for KAT")

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// TestMLDSA65KAT_KeygenDeterminism verifies that keygen from a fixed seed
// produces the expected public key. This catches regressions in the
// underlying lattice arithmetic or encoding.
func TestMLDSA65KAT_KeygenDeterminism(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	pk, _ := mldsa65.NewKeyFromSeed(&seedArr)
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	expectedPrefix := mustDecodeHex(t, katPKPrefixHex)
	if !bytes.Equal(pkBytes[:32], expectedPrefix) {
		t.Fatalf("public key prefix mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(pkBytes[:32]), katPKPrefixHex)
	}

	if len(pkBytes) != MLDSA65PublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pkBytes), MLDSA65PublicKeySize)
	}
}

// TestMLDSA65KAT_SignDeterminism verifies that non-randomized signing
// with a known key and message produces the expected signature bytes.
func TestMLDSA65KAT_SignDeterminism(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	_, sk := mldsa65.NewKeyFromSeed(&seedArr)

	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, katMessage, nil, false, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	expectedPrefix := mustDecodeHex(t, katSigPrefixHex)
	if !bytes.Equal(sig[:32], expectedPrefix) {
		t.Fatalf("signature prefix mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(sig[:32]), katSigPrefixHex)
	}

	if len(sig) != MLDSA65SignatureSize {
		t.Fatalf("signature size: got %d, want %d", len(sig), MLDSA65SignatureSize)
	}
}

// TestMLDSA65KAT_VerifyKnownGood verifies that a known-good signature
// from the KAT vector passes verification.
func TestMLDSA65KAT_VerifyKnownGood(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	pk, sk := mldsa65.NewKeyFromSeed(&seedArr)

	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, katMessage, nil, false, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	if !mldsa65.Verify(pk, katMessage, nil, sig) {
		t.Fatal("verification failed for known-good KAT signature")
	}
}

// TestMLDSA65KAT_VerifyRejectsWrongMessage verifies that the KAT signature
// is rejected when verified against a different message.
func TestMLDSA65KAT_VerifyRejectsWrongMessage(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	pk, sk := mldsa65.NewKeyFromSeed(&seedArr)

	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, katMessage, nil, false, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	wrongMessage := []byte("wrong message")
	if mldsa65.Verify(pk, wrongMessage, nil, sig) {
		t.Fatal("verification should fail for wrong message")
	}
}

// TestMLDSA65KAT_VerifyRejectsTamperedSig verifies that a corrupted
// signature is rejected.
func TestMLDSA65KAT_VerifyRejectsTamperedSig(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	pk, sk := mldsa65.NewKeyFromSeed(&seedArr)

	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, katMessage, nil, false, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	// Flip bits in the signature.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF

	if mldsa65.Verify(pk, katMessage, nil, tampered) {
		t.Fatal("verification should fail for tampered signature")
	}
}

// TestMLDSA65KAT_WrapperRoundtrip verifies that the mldsa package wrapper
// correctly round-trips keys generated from the same seed through its
// serialization API and that sign/verify work end-to-end.
func TestMLDSA65KAT_WrapperRoundtrip(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	// Generate via circl directly.
	circlPK, circlSK := mldsa65.NewKeyFromSeed(&seedArr)
	skBytes, err := circlSK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(sk): %v", err)
	}
	pkBytes, err := circlPK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(pk): %v", err)
	}

	// Import into wrapper types.
	sk, err := PrivateKeyFromBytes(MLDSA65, skBytes)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes: %v", err)
	}

	pk, err := PublicKeyFromBytes(pkBytes, MLDSA65)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}

	// Sign with wrapper, verify with wrapper.
	sig, err := sk.Sign(nil, katMessage, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !pk.VerifySignature(katMessage, sig) {
		t.Fatal("wrapper verify failed for wrapper-signed message")
	}

	// Verify wrapper public key matches circl public key.
	if !bytes.Equal(pk.Bytes(), pkBytes) {
		t.Fatal("wrapper public key bytes do not match circl public key bytes")
	}
}

// TestMLDSA65KAT_SeedStability verifies that generating keys twice from the
// same seed produces identical key material. This is the core determinism
// property required by FIPS 204.
func TestMLDSA65KAT_SeedStability(t *testing.T) {
	seed := mustDecodeHex(t, katSeedHex)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)

	pk1, sk1 := mldsa65.NewKeyFromSeed(&seedArr)
	pk2, sk2 := mldsa65.NewKeyFromSeed(&seedArr)

	pk1Bytes, _ := pk1.MarshalBinary()
	pk2Bytes, _ := pk2.MarshalBinary()
	sk1Bytes, _ := sk1.MarshalBinary()
	sk2Bytes, _ := sk2.MarshalBinary()

	if !bytes.Equal(pk1Bytes, pk2Bytes) {
		t.Fatal("public keys differ for same seed")
	}
	if !bytes.Equal(sk1Bytes, sk2Bytes) {
		t.Fatal("private keys differ for same seed")
	}
}

// TestMLDSA65KAT_AllModes verifies deterministic keygen works for all three
// ML-DSA security levels via the circl scheme API.
func TestMLDSA65KAT_AllModes(t *testing.T) {
	modes := []struct {
		name    string
		mode    Mode
		pkSize  int
		skSize  int
		sigSize int
	}{
		{"ML-DSA-44", MLDSA44, MLDSA44PublicKeySize, MLDSA44PrivateKeySize, MLDSA44SignatureSize},
		{"ML-DSA-65", MLDSA65, MLDSA65PublicKeySize, MLDSA65PrivateKeySize, MLDSA65SignatureSize},
		{"ML-DSA-87", MLDSA87, MLDSA87PublicKeySize, MLDSA87PrivateKeySize, MLDSA87SignatureSize},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key pair using deterministic reader.
			seed := make([]byte, 256)
			for i := range seed {
				seed[i] = byte(i ^ int(tt.mode))
			}
			reader := bytes.NewReader(seed)

			sk, err := GenerateKey(reader, tt.mode)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			if len(sk.Bytes()) != tt.skSize {
				t.Fatalf("private key size: got %d, want %d", len(sk.Bytes()), tt.skSize)
			}
			if len(sk.PublicKey.Bytes()) != tt.pkSize {
				t.Fatalf("public key size: got %d, want %d", len(sk.PublicKey.Bytes()), tt.pkSize)
			}

			// Sign and verify.
			msg := []byte("KAT message for " + tt.name)
			sig, err := sk.Sign(nil, msg, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) != tt.sigSize {
				t.Fatalf("signature size: got %d, want %d", len(sig), tt.sigSize)
			}
			if !sk.PublicKey.VerifySignature(msg, sig) {
				t.Fatal("verification failed")
			}
		})
	}
}
