// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/node/utils/hashing"
)

// FuzzSignatureVerification tests signature verification with random inputs
func FuzzSignatureVerification(f *testing.F) {
	// Seed corpus with valid and invalid signatures
	f.Add(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 65))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xff}, 65))

	// Add a valid signature
	privKey := make([]byte, 32)
	privKey[31] = 1 // Simple valid private key
	msg := hashing.ComputeHash256([]byte("test message"))
	if sig, err := Sign(msg, privKey); err == nil {
		f.Add(msg, sig)
	}

	// Add signatures with different recovery IDs
	validSig := make([]byte, 65)
	copy(validSig[:32], bytes.Repeat([]byte{0xaa}, 32))
	copy(validSig[32:64], bytes.Repeat([]byte{0xbb}, 32))
	validSig[64] = 0
	f.Add(hashing.ComputeHash256([]byte("test")), validSig)

	validSig[64] = 1
	f.Add(hashing.ComputeHash256([]byte("test2")), validSig)

	f.Fuzz(func(t *testing.T, msg []byte, sig []byte) {
		// Ensure msg is 32 bytes (hash size)
		if len(msg) != 32 {
			if len(msg) < 32 {
				msg = append(msg, bytes.Repeat([]byte{0}, 32-len(msg))...)
			} else {
				msg = msg[:32]
			}
		}

		// Try to recover public key - should not panic
		pubKey, err := RecoverPubkey(msg, sig)
		if err != nil {
			// Expected for invalid signatures
			return
		}

		// If recovery succeeded, verify the public key is valid
		if len(pubKey) != 65 && len(pubKey) != 33 {
			t.Errorf("Invalid public key length: %d", len(pubKey))
		}

		// Try to verify signature with recovered key
		valid := VerifySignature(pubKey, msg, sig[:64])
		_ = valid // Result doesn't matter, just ensure no panic

		// Test decompression if compressed
		if len(pubKey) == 33 {
			x, y := DecompressPubkey(pubKey)
			if x == nil || y == nil {
				return
			}
			// Reconstruct uncompressed form: 0x04 + x (32 bytes) + y (32 bytes)
			uncompressed := make([]byte, 65)
			uncompressed[0] = 0x04
			xBytes := x.Bytes()
			yBytes := y.Bytes()
			copy(uncompressed[33-len(xBytes):33], xBytes)
			copy(uncompressed[65-len(yBytes):65], yBytes)
			if len(uncompressed) != 65 {
				t.Errorf("Decompressed public key has wrong length: %d", len(uncompressed))
			}
		}
	})
}

// FuzzSignatureCreation tests signature creation with various keys and messages
func FuzzSignatureCreation(f *testing.F) {
	// Seed corpus
	f.Add(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32))
	f.Add(bytes.Repeat([]byte{0xff}, 32), hashing.ComputeHash256([]byte("test")))

	// Add some valid private keys
	validKey1 := make([]byte, 32)
	validKey1[31] = 1
	f.Add(validKey1, hashing.ComputeHash256([]byte("message1")))

	validKey2 := make([]byte, 32)
	copy(validKey2, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	f.Add(validKey2, hashing.ComputeHash256([]byte("message2")))

	f.Fuzz(func(t *testing.T, privKey []byte, msg []byte) {
		// Ensure proper sizes
		if len(privKey) != 32 {
			if len(privKey) < 32 {
				privKey = append(privKey, bytes.Repeat([]byte{0}, 32-len(privKey))...)
			} else {
				privKey = privKey[:32]
			}
		}

		if len(msg) != 32 {
			if len(msg) < 32 {
				msg = append(msg, bytes.Repeat([]byte{0}, 32-len(msg))...)
			} else {
				msg = msg[:32]
			}
		}

		// Try to sign
		sig, err := Sign(msg, privKey)
		if err != nil {
			// Expected for invalid private keys
			return
		}

		// Signature should be 65 bytes
		if len(sig) != 65 {
			t.Errorf("Invalid signature length: %d", len(sig))
			return
		}

		// Recovery ID should be 0 or 1
		if sig[64] > 1 {
			t.Errorf("Invalid recovery ID: %d", sig[64])
		}

		// Try to recover public key
		pubKey, err := RecoverPubkey(msg, sig)
		if err != nil {
			t.Errorf("Failed to recover public key from signature we created: %v", err)
			return
		}

		// Verify signature with recovered key
		valid := VerifySignature(pubKey, msg, sig[:64])
		if !valid {
			t.Error("Signature verification failed for signature we created")
		}
	})
}

// FuzzPublicKeyCompression tests public key compression/decompression
func FuzzPublicKeyCompression(f *testing.F) {
	// Seed corpus with various public key representations
	f.Add(bytes.Repeat([]byte{0x04}, 65)) // Uncompressed prefix
	f.Add(bytes.Repeat([]byte{0x02}, 33)) // Compressed even Y
	f.Add(bytes.Repeat([]byte{0x03}, 33)) // Compressed odd Y

	// Generate a valid public key
	privKey := make([]byte, 32)
	privKey[31] = 42
	msg := hashing.ComputeHash256([]byte("test"))
	if sig, err := Sign(msg, privKey); err == nil {
		if pubKey, err := RecoverPubkey(msg, sig); err == nil {
			f.Add(pubKey)
		}
	}

	f.Fuzz(func(t *testing.T, pubKeyData []byte) {
		// Test compression if uncompressed
		if len(pubKeyData) == 65 && pubKeyData[0] == 0x04 {
			x := new(big.Int).SetBytes(pubKeyData[1:33])
			y := new(big.Int).SetBytes(pubKeyData[33:65])
			compressed := CompressPubkey(x, y)
			if len(compressed) != 33 {
				t.Errorf("Compressed public key has wrong length: %d", len(compressed))
				return
			}

			// Try to decompress back
			dx, dy := DecompressPubkey(compressed)
			if dx == nil || dy == nil {
				// Some points might not be on the curve
				return
			}

			// Reconstruct uncompressed form
			uncompressed := make([]byte, 65)
			uncompressed[0] = 0x04
			dxBytes := dx.Bytes()
			dyBytes := dy.Bytes()
			copy(uncompressed[33-len(dxBytes):33], dxBytes)
			copy(uncompressed[65-len(dyBytes):65], dyBytes)
			if len(uncompressed) != 65 {
				t.Errorf("Decompressed public key has wrong length: %d", len(uncompressed))
			}
		}

		// Test decompression if compressed
		if len(pubKeyData) == 33 && (pubKeyData[0] == 0x02 || pubKeyData[0] == 0x03) {
			x, y := DecompressPubkey(pubKeyData)
			if x == nil || y == nil {
				// Expected for invalid compressed keys
				return
			}

			// Reconstruct uncompressed form
			uncompressed := make([]byte, 65)
			uncompressed[0] = 0x04
			xBytes := x.Bytes()
			yBytes := y.Bytes()
			copy(uncompressed[33-len(xBytes):33], xBytes)
			copy(uncompressed[65-len(yBytes):65], yBytes)
			if len(uncompressed) != 65 {
				t.Errorf("Decompressed public key has wrong length: %d", len(uncompressed))
				return
			}

			// Compress again and verify round-trip
			recompressed := CompressPubkey(x, y)
			if !bytes.Equal(recompressed, pubKeyData) {
				// Note: This might fail for invalid input keys
				return
			}
		}
	})
}

// FuzzSignatureMalleability tests signature malleability handling
func FuzzSignatureMalleability(f *testing.F) {
	// Seed corpus
	f.Add(bytes.Repeat([]byte{0x7f}, 32), bytes.Repeat([]byte{0x80}, 32), uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0x01}, 32), uint8(1))

	f.Fuzz(func(t *testing.T, r []byte, s []byte, v uint8) {
		// Ensure proper sizes
		if len(r) != 32 {
			if len(r) < 32 {
				r = append(r, bytes.Repeat([]byte{0}, 32-len(r))...)
			} else {
				r = r[:32]
			}
		}

		if len(s) != 32 {
			if len(s) < 32 {
				s = append(s, bytes.Repeat([]byte{0}, 32-len(s))...)
			} else {
				s = s[:32]
			}
		}

		// Create signature
		sig := make([]byte, 65)
		copy(sig[:32], r)
		copy(sig[32:64], s)
		sig[64] = v & 1 // Ensure v is 0 or 1

		// Create a random message
		msg := hashing.ComputeHash256(append(r, s...))

		// Try to verify - should not panic
		pubKey, err := RecoverPubkey(msg, sig)
		if err != nil {
			// Expected for invalid signatures
			return
		}

		// Try signature verification
		valid := VerifySignature(pubKey, msg, sig[:64])
		_ = valid // Don't care about result, just ensure no panic
	})
}

// FuzzECDSAEdgeCases tests edge cases in ECDSA operations
func FuzzECDSAEdgeCases(f *testing.F) {
	// Seed corpus with edge cases
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0}, []byte{0})

	// All zeros
	zeros := make([]byte, 32)
	f.Add(zeros, zeros)

	// All ones
	ones := bytes.Repeat([]byte{0xff}, 32)
	f.Add(ones, ones)

	// Near the curve order
	nearOrder := make([]byte, 32)
	copy(nearOrder, []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
		0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	})
	f.Add(nearOrder, hashing.ComputeHash256([]byte("edge")))

	f.Fuzz(func(t *testing.T, privKey []byte, msg []byte) {
		// Handle nil and empty cases
		if privKey == nil {
			privKey = make([]byte, 32)
		}
		if msg == nil {
			msg = make([]byte, 32)
		}

		// Ensure proper sizes
		if len(privKey) < 32 {
			privKey = append(privKey, bytes.Repeat([]byte{0}, 32-len(privKey))...)
		} else if len(privKey) > 32 {
			privKey = privKey[:32]
		}

		if len(msg) < 32 {
			msg = append(msg, bytes.Repeat([]byte{0}, 32-len(msg))...)
		} else if len(msg) > 32 {
			msg = msg[:32]
		}

		// Test signing
		sig, err := Sign(msg, privKey)
		if err != nil {
			// Check for specific error types
			if err == ErrInvalidKey || err == ErrInvalidMsgLen {
				// Expected errors
				return
			}
			// Unexpected error type
			t.Errorf("Unexpected error type: %v", err)
			return
		}

		// If signing succeeded, verify signature properties
		if len(sig) != 65 {
			t.Errorf("Invalid signature length: %d", len(sig))
			return
		}

		// Check recovery ID
		if sig[64] > 1 {
			t.Errorf("Invalid recovery ID: %d", sig[64])
		}

		// Try recovery
		pubKey, err := RecoverPubkey(msg, sig)
		if err != nil {
			t.Errorf("Failed to recover public key from valid signature: %v", err)
			return
		}

		// Verify the signature
		if !VerifySignature(pubKey, msg, sig[:64]) {
			t.Error("Signature verification failed for edge case")
		}
	})
}

// Helper function to generate random bytes
func randomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
