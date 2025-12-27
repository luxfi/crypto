// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// KAT (Known Answer Test) vectors for ML-KEM-768 (FIPS 203, NIST Level 3).
//
// These are deterministic test vectors generated from fixed seeds using
// circl's NewKeyFromSeed and deterministic EncapsulateTo. The key prefix,
// ciphertext prefix, and shared secret are pinned to detect any change in
// the underlying implementation across library upgrades.

// katKeySeedHex is the 64-byte keygen seed (0x00..0x3f).
const katKeySeedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
	"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

// katPKPrefixHex is the first 32 bytes of the expected public key.
const katPKPrefixHex = "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672c"

// katSKPrefixHex is the first 32 bytes of the expected private key.
const katSKPrefixHex = "27d2a77f33756f61208ef113abe82595873d4abc730e5b5d679529bf6a4ceb63"

// katEncapSeedHex is the 32-byte encapsulation seed (0x40..0x5f).
const katEncapSeedHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

// katCTPrefixHex is the first 32 bytes of the expected ciphertext.
const katCTPrefixHex = "695a60d9c79f08343ed9ff5802582063c2ca3a648e543d924affbb39ef4de656"

// katSharedSecretHex is the full 32-byte expected shared secret.
const katSharedSecretHex = "9cddd089ffe70e3996e76f7c8d06746df34d07e8657bc0fcf2bb0e1c3084aea1"

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// TestMLKEM768KAT_KeygenDeterminism verifies that keygen from a fixed seed
// produces the expected public and private keys.
func TestMLKEM768KAT_KeygenDeterminism(t *testing.T) {
	seed := mustDecodeHex(t, katKeySeedHex)

	pk, sk := mlkem768.NewKeyFromSeed(seed)

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(pk): %v", err)
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(sk): %v", err)
	}

	expectedPKPrefix := mustDecodeHex(t, katPKPrefixHex)
	if !bytes.Equal(pkBytes[:32], expectedPKPrefix) {
		t.Fatalf("public key prefix mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(pkBytes[:32]), katPKPrefixHex)
	}

	expectedSKPrefix := mustDecodeHex(t, katSKPrefixHex)
	if !bytes.Equal(skBytes[:32], expectedSKPrefix) {
		t.Fatalf("private key prefix mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(skBytes[:32]), katSKPrefixHex)
	}

	if len(pkBytes) != MLKEM768PublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pkBytes), MLKEM768PublicKeySize)
	}
	if len(skBytes) != MLKEM768PrivateKeySize {
		t.Fatalf("private key size: got %d, want %d", len(skBytes), MLKEM768PrivateKeySize)
	}
}

// TestMLKEM768KAT_EncapsulateDeterminism verifies that deterministic
// encapsulation with a known seed produces the expected ciphertext
// and shared secret.
func TestMLKEM768KAT_EncapsulateDeterminism(t *testing.T) {
	keySeed := mustDecodeHex(t, katKeySeedHex)
	pk, _ := mlkem768.NewKeyFromSeed(keySeed)

	encapSeed := mustDecodeHex(t, katEncapSeedHex)
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(ct, ss, encapSeed)

	expectedCTPrefix := mustDecodeHex(t, katCTPrefixHex)
	if !bytes.Equal(ct[:32], expectedCTPrefix) {
		t.Fatalf("ciphertext prefix mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(ct[:32]), katCTPrefixHex)
	}

	expectedSS := mustDecodeHex(t, katSharedSecretHex)
	if !bytes.Equal(ss, expectedSS) {
		t.Fatalf("shared secret mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(ss), katSharedSecretHex)
	}
}

// TestMLKEM768KAT_DecapsulateRecovery verifies that decapsulation of the
// KAT ciphertext recovers the same shared secret.
func TestMLKEM768KAT_DecapsulateRecovery(t *testing.T) {
	keySeed := mustDecodeHex(t, katKeySeedHex)
	pk, sk := mlkem768.NewKeyFromSeed(keySeed)

	// Encapsulate deterministically.
	encapSeed := mustDecodeHex(t, katEncapSeedHex)
	ct := make([]byte, mlkem768.CiphertextSize)
	ssEncap := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(ct, ssEncap, encapSeed)

	// Decapsulate.
	ssDecap := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ssDecap, ct)

	if !bytes.Equal(ssEncap, ssDecap) {
		t.Fatalf("shared secret mismatch after decapsulation\n  encap: %s\n  decap: %s",
			hex.EncodeToString(ssEncap), hex.EncodeToString(ssDecap))
	}

	expectedSS := mustDecodeHex(t, katSharedSecretHex)
	if !bytes.Equal(ssDecap, expectedSS) {
		t.Fatalf("decapsulated shared secret does not match KAT\n  got:  %s\n  want: %s",
			hex.EncodeToString(ssDecap), katSharedSecretHex)
	}
}

// TestMLKEM768KAT_ImplicitRejection verifies that decapsulating a tampered
// ciphertext produces a different shared secret (implicit rejection per
// FIPS 203 Section 7.3) rather than an error.
func TestMLKEM768KAT_ImplicitRejection(t *testing.T) {
	keySeed := mustDecodeHex(t, katKeySeedHex)
	pk, sk := mlkem768.NewKeyFromSeed(keySeed)

	encapSeed := mustDecodeHex(t, katEncapSeedHex)
	ct := make([]byte, mlkem768.CiphertextSize)
	ssGood := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(ct, ssGood, encapSeed)

	// Tamper with ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xFF

	ssBad := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ssBad, tampered)

	if bytes.Equal(ssGood, ssBad) {
		t.Fatal("tampered ciphertext produced same shared secret (implicit rejection failed)")
	}
}

// TestMLKEM768KAT_SeedStability verifies that generating keys twice from
// the same seed produces identical key material.
func TestMLKEM768KAT_SeedStability(t *testing.T) {
	seed := mustDecodeHex(t, katKeySeedHex)

	pk1, sk1 := mlkem768.NewKeyFromSeed(seed)
	pk2, sk2 := mlkem768.NewKeyFromSeed(seed)

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

// TestMLKEM768KAT_WrapperRoundtrip verifies that the mlkem package wrapper
// correctly round-trips keys generated from a fixed seed through its
// serialization API and that encapsulate/decapsulate work end-to-end.
func TestMLKEM768KAT_WrapperRoundtrip(t *testing.T) {
	seed := mustDecodeHex(t, katKeySeedHex)

	// Generate via circl directly.
	circlPK, circlSK := mlkem768.NewKeyFromSeed(seed)
	pkBytes, err := circlPK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(pk): %v", err)
	}
	skBytes, err := circlSK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(sk): %v", err)
	}

	// Import into wrapper types.
	pub, err := PublicKeyFromBytes(pkBytes, MLKEM768)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	priv, err := PrivateKeyFromBytes(skBytes, MLKEM768)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes: %v", err)
	}

	// Encapsulate via wrapper.
	ct, ssEncap, err := pub.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	if len(ct) != MLKEM768CiphertextSize {
		t.Fatalf("ciphertext size: got %d, want %d", len(ct), MLKEM768CiphertextSize)
	}

	// Decapsulate via wrapper.
	ssDecap, err := priv.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(ssEncap, ssDecap) {
		t.Fatalf("wrapper roundtrip shared secret mismatch\n  encap: %s\n  decap: %s",
			hex.EncodeToString(ssEncap), hex.EncodeToString(ssDecap))
	}

	// Verify wrapper key bytes match circl key bytes.
	if !bytes.Equal(pub.Bytes(), pkBytes) {
		t.Fatal("wrapper public key bytes do not match circl bytes")
	}
	if !bytes.Equal(priv.Bytes(), skBytes) {
		t.Fatal("wrapper private key bytes do not match circl bytes")
	}
}

// TestMLKEM768KAT_AllModes verifies deterministic keygen and encap/decap
// roundtrip for all three ML-KEM security levels.
func TestMLKEM768KAT_AllModes(t *testing.T) {
	modes := []struct {
		name   string
		mode   Mode
		pkSize int
		skSize int
		ctSize int
		ssSize int
	}{
		{"ML-KEM-512", MLKEM512, MLKEM512PublicKeySize, MLKEM512PrivateKeySize, MLKEM512CiphertextSize, MLKEM512SharedKeySize},
		{"ML-KEM-768", MLKEM768, MLKEM768PublicKeySize, MLKEM768PrivateKeySize, MLKEM768CiphertextSize, MLKEM768SharedKeySize},
		{"ML-KEM-1024", MLKEM1024, MLKEM1024PublicKeySize, MLKEM1024PrivateKeySize, MLKEM1024CiphertextSize, MLKEM1024SharedKeySize},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			// Generate keys via wrapper with deterministic reader.
			seed := make([]byte, 256)
			for i := range seed {
				seed[i] = byte(i ^ int(tt.mode))
			}
			reader := bytes.NewReader(seed)

			pub, priv, err := GenerateKeyPair(reader, tt.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair: %v", err)
			}

			if len(pub.Bytes()) != tt.pkSize {
				t.Fatalf("public key size: got %d, want %d", len(pub.Bytes()), tt.pkSize)
			}
			if len(priv.Bytes()) != tt.skSize {
				t.Fatalf("private key size: got %d, want %d", len(priv.Bytes()), tt.skSize)
			}

			// Encapsulate and decapsulate.
			ct, ssEncap, err := pub.Encapsulate()
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			if len(ct) != tt.ctSize {
				t.Fatalf("ciphertext size: got %d, want %d", len(ct), tt.ctSize)
			}

			ssDecap, err := priv.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}

			if !bytes.Equal(ssEncap, ssDecap) {
				t.Fatal("shared secret mismatch")
			}
			if len(ssDecap) != tt.ssSize {
				t.Fatalf("shared secret size: got %d, want %d", len(ssDecap), tt.ssSize)
			}
		})
	}
}
