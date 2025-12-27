// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// FuzzMLKEMEncapsDecaps tests that encapsulate/decapsulate roundtrips correctly,
// producing the same shared secret on both sides for arbitrary randomness.
func FuzzMLKEMEncapsDecaps(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(1))
	f.Add(uint8(2))

	f.Fuzz(func(t *testing.T, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		pk, sk, err := GenerateKey(mode)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", mode, err)
		}

		ct, sharedKey1, err := pk.Encapsulate()
		if err != nil {
			t.Fatalf("Encapsulate: %v", err)
		}

		expectedCTSize := GetCiphertextSize(mode)
		if len(ct) != expectedCTSize {
			t.Fatalf("ciphertext size = %d, want %d", len(ct), expectedCTSize)
		}

		sharedKey2, err := sk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulate: %v", err)
		}

		if !bytes.Equal(sharedKey1, sharedKey2) {
			t.Fatal("shared secrets do not match")
		}

		// Verify key serialization roundtrip
		pkBytes := pk.Bytes()
		pk2, err := PublicKeyFromBytes(pkBytes, mode)
		if err != nil {
			t.Fatalf("PublicKeyFromBytes: %v", err)
		}

		skBytes := sk.Bytes()
		sk2, err := PrivateKeyFromBytes(skBytes, mode)
		if err != nil {
			t.Fatalf("PrivateKeyFromBytes: %v", err)
		}

		// Encapsulate with deserialized public key
		ct2, sharedKey3, err := pk2.Encapsulate()
		if err != nil {
			t.Fatalf("Encapsulate with deserialized pk: %v", err)
		}

		// Decapsulate with deserialized private key
		sharedKey4, err := sk2.Decapsulate(ct2)
		if err != nil {
			t.Fatalf("Decapsulate with deserialized sk: %v", err)
		}

		if !bytes.Equal(sharedKey3, sharedKey4) {
			t.Fatal("shared secrets do not match after key deserialization")
		}
	})
}

// FuzzMLKEMMalformedCiphertext tests that Decapsulate doesn't panic on garbage ciphertext.
// ML-KEM is designed to be implicitly rejection-safe: decapsulating an invalid
// ciphertext produces a pseudorandom shared secret rather than an error (FO transform).
// We verify no panics occur regardless of ciphertext content.
func FuzzMLKEMMalformedCiphertext(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0x00}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 768), uint8(0))  // MLKEM512 ct size
	f.Add(bytes.Repeat([]byte{0xaa}, 1088), uint8(1)) // MLKEM768 ct size
	f.Add(bytes.Repeat([]byte{0xbb}, 1568), uint8(2)) // MLKEM1024 ct size
	f.Add(bytes.Repeat([]byte{0x00}, 1088), uint8(1))
	f.Add(bytes.Repeat([]byte{0xde, 0xad}, 800), uint8(2))

	f.Fuzz(func(t *testing.T, garbageCT []byte, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		_, sk, err := GenerateKey(mode)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", mode, err)
		}

		// Must not panic. May return error for wrong-size ciphertext.
		sharedKey, err := sk.Decapsulate(garbageCT)

		expectedCTSize := GetCiphertextSize(mode)
		if len(garbageCT) != expectedCTSize {
			// Wrong-size ciphertext must be rejected.
			if err == nil {
				t.Fatal("Decapsulate accepted wrong-size ciphertext")
			}
			return
		}

		// For correct-size garbage ciphertext, ML-KEM's implicit rejection
		// means decaps should succeed (returning a pseudorandom key) or
		// return an error. Either is acceptable; panic is not.
		if err != nil {
			return
		}

		// If decapsulation succeeded, shared key should be non-empty.
		if len(sharedKey) == 0 {
			t.Fatal("Decapsulate returned empty shared key without error")
		}
	})
}

// FuzzMLKEMMalformedPublicKey tests that Encapsulate doesn't panic on garbage public keys.
// Exercises both PublicKeyFromBytes deserialization and Encapsulate with the result.
func FuzzMLKEMMalformedPublicKey(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 48), uint8(0))
	f.Add(bytes.Repeat([]byte{0x00}, 800), uint8(0))  // MLKEM512 pk size
	f.Add(bytes.Repeat([]byte{0xaa}, 1184), uint8(1)) // MLKEM768 pk size
	f.Add(bytes.Repeat([]byte{0xbb}, 1568), uint8(2)) // MLKEM1024 pk size
	f.Add(bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 300), uint8(1))

	f.Fuzz(func(t *testing.T, garbagePK []byte, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		// PublicKeyFromBytes must not panic.
		pk, err := PublicKeyFromBytes(garbagePK, mode)
		if err != nil {
			// Expected for most garbage inputs (wrong size, invalid encoding).
			return
		}

		// If deserialization succeeded, Encapsulate must not panic.
		ct, sharedKey, err := pk.Encapsulate()
		if err != nil {
			// Some garbage keys may parse but fail during encapsulation.
			return
		}

		// If encapsulation succeeded, outputs should be non-empty.
		if len(ct) == 0 {
			t.Fatal("Encapsulate returned empty ciphertext without error")
		}
		if len(sharedKey) == 0 {
			t.Fatal("Encapsulate returned empty shared key without error")
		}

		// Verify ciphertext size matches expected for the mode.
		expectedCTSize := GetCiphertextSize(mode)
		if len(ct) != expectedCTSize {
			t.Fatalf("ciphertext size = %d, want %d", len(ct), expectedCTSize)
		}
	})
}

// FuzzMLKEMKeySerializationRoundtrip tests that key serialization/deserialization
// roundtrips without losing data.
func FuzzMLKEMKeySerializationRoundtrip(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(1))
	f.Add(uint8(2))

	f.Fuzz(func(t *testing.T, modeIdx uint8) {
		mode := Mode(modeIdx % 3)

		pk, sk, err := GenerateKey(mode)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", mode, err)
		}

		// Public key roundtrip
		pkBytes := pk.Bytes()
		pk2, err := PublicKeyFromBytes(pkBytes, mode)
		if err != nil {
			t.Fatalf("PublicKeyFromBytes: %v", err)
		}
		if !bytes.Equal(pk.Bytes(), pk2.Bytes()) {
			t.Fatal("public key bytes changed after roundtrip")
		}

		// Private key roundtrip
		skBytes := sk.Bytes()
		sk2, err := PrivateKeyFromBytes(skBytes, mode)
		if err != nil {
			t.Fatalf("PrivateKeyFromBytes: %v", err)
		}
		if !bytes.Equal(sk.Bytes(), sk2.Bytes()) {
			t.Fatal("private key bytes changed after roundtrip")
		}

		// Cross-key compatibility: encaps with pk, decaps with deserialized sk
		ct, ss1, err := pk.Encapsulate(rand.Reader)
		if err != nil {
			t.Fatalf("Encapsulate: %v", err)
		}
		ss2, err := sk2.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulate with deserialized sk: %v", err)
		}
		if !bytes.Equal(ss1, ss2) {
			t.Fatal("shared secrets differ after private key deserialization")
		}
	})
}
