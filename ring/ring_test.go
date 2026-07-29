// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemeString(t *testing.T) {
	require.Equal(t, "LSAG", LSAG.String())
	require.Equal(t, "Lattice-LSAG", LatticeLSAG.String())
	require.Equal(t, "DualRing", DualRing.String())
	require.Equal(t, "unknown", Scheme(99).String())
}

func TestMemoryKeyImageStore(t *testing.T) {
	store := NewMemoryKeyImageStore()

	keyImage1 := []byte("key-image-1")
	keyImage2 := []byte("key-image-2")

	// Initially empty
	require.False(t, store.HasKeyImage(keyImage1))
	require.False(t, store.HasKeyImage(keyImage2))

	// Add first key image
	err := store.AddKeyImage(keyImage1)
	require.NoError(t, err)
	require.True(t, store.HasKeyImage(keyImage1))
	require.False(t, store.HasKeyImage(keyImage2))

	// Double-add should fail
	err = store.AddKeyImage(keyImage1)
	require.ErrorIs(t, err, ErrKeyImageReused)

	// Add second key image
	err = store.AddKeyImage(keyImage2)
	require.NoError(t, err)
	require.True(t, store.HasKeyImage(keyImage2))

	// Remove first key image
	err = store.RemoveKeyImage(keyImage1)
	require.NoError(t, err)
	require.False(t, store.HasKeyImage(keyImage1))
	require.True(t, store.HasKeyImage(keyImage2))
}

func TestLSAGSignerCreation(t *testing.T) {
	// Create signer with random key
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.Equal(t, LSAG, signer.Scheme())

	// Public key should be 33 bytes (compressed)
	pubKey := signer.PublicKey()
	require.Len(t, pubKey, 33)

	// Key image should be 33 bytes
	keyImage := signer.KeyImage()
	require.Len(t, keyImage, 33)
}

func TestLSAGSignerFromPrivateKey(t *testing.T) {
	// Generate private key
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	require.NoError(t, err)

	// Create signer from private key
	signer, err := NewSignerFromPrivateKey(LSAG, privateKey)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Create another signer from same key
	signer2, err := NewSignerFromPrivateKey(LSAG, privateKey)
	require.NoError(t, err)

	// Public keys should match
	require.Equal(t, signer.PublicKey(), signer2.PublicKey())

	// Key images should match (linkability)
	require.Equal(t, signer.KeyImage(), signer2.KeyImage())
}

func TestLSAGSignAndVerify(t *testing.T) {
	// Create signer
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	// Create ring with decoy public keys
	ringSize := 5
	signerIndex := 2
	ring := make([][]byte, ringSize)

	for i := 0; i < ringSize; i++ {
		if i == signerIndex {
			ring[i] = signer.PublicKey()
		} else {
			decoy, err := NewSigner(LSAG)
			require.NoError(t, err)
			ring[i] = decoy.PublicKey()
		}
	}

	// Sign message
	message := []byte("test message for ring signature")
	sig, err := signer.Sign(message, ring, signerIndex)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify signature
	require.True(t, sig.Verify(message, ring), "valid signature should verify")
	require.Equal(t, ringSize, sig.RingSize())
	require.Equal(t, LSAG, sig.Scheme())

	// Key image should match signer's key image
	require.Equal(t, signer.KeyImage(), sig.KeyImage())
}

func TestLSAGSignatureInvalidMessage(t *testing.T) {
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LSAG)
		ring[i] = decoy.PublicKey()
	}

	message := []byte("original message")
	sig, err := signer.Sign(message, ring, 0)
	require.NoError(t, err)

	// Should fail with different message
	wrongMessage := []byte("wrong message")
	require.False(t, sig.Verify(wrongMessage, ring), "signature should not verify with wrong message")
}

func TestLSAGSignatureInvalidRing(t *testing.T) {
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LSAG)
		ring[i] = decoy.PublicKey()
	}

	message := []byte("test message")
	sig, err := signer.Sign(message, ring, 0)
	require.NoError(t, err)

	// Modify ring (replace a key)
	wrongRing := make([][]byte, len(ring))
	copy(wrongRing, ring)
	decoy, _ := NewSigner(LSAG)
	wrongRing[1] = decoy.PublicKey()

	require.False(t, sig.Verify(message, wrongRing), "signature should not verify with modified ring")
}

func TestLSAGSignatureSerialization(t *testing.T) {
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	ring := make([][]byte, 4)
	ring[1] = signer.PublicKey()
	for i := 0; i < 4; i++ {
		if i != 1 {
			decoy, _ := NewSigner(LSAG)
			ring[i] = decoy.PublicKey()
		}
	}

	message := []byte("serialization test")
	sig, err := signer.Sign(message, ring, 1)
	require.NoError(t, err)

	// Serialize
	data := sig.Bytes()
	require.NotEmpty(t, data)

	// Deserialize
	parsed, err := ParseSignature(LSAG, data)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Verify parsed signature
	require.True(t, parsed.Verify(message, ring))
	require.Equal(t, sig.KeyImage(), parsed.KeyImage())
	require.Equal(t, sig.RingSize(), parsed.RingSize())
}

func TestLSAGKeyImageLinkability(t *testing.T) {
	// Create signer
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	// Create ring
	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LSAG)
		ring[i] = decoy.PublicKey()
	}

	// Sign two different messages
	msg1 := []byte("message 1")
	msg2 := []byte("message 2")

	sig1, err := signer.Sign(msg1, ring, 0)
	require.NoError(t, err)

	sig2, err := signer.Sign(msg2, ring, 0)
	require.NoError(t, err)

	// Key images should be the same (linkable)
	require.Equal(t, sig1.KeyImage(), sig2.KeyImage(), "key images should match for same signer")

	// Different signer should have different key image
	otherSigner, _ := NewSigner(LSAG)
	otherRing := make([][]byte, 3)
	otherRing[0] = otherSigner.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LSAG)
		otherRing[i] = decoy.PublicKey()
	}

	sig3, err := otherSigner.Sign(msg1, otherRing, 0)
	require.NoError(t, err)

	require.NotEqual(t, sig1.KeyImage(), sig3.KeyImage(), "different signers should have different key images")
}

func TestLSAGDoubleSpendDetection(t *testing.T) {
	store := NewMemoryKeyImageStore()
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LSAG)
		ring[i] = decoy.PublicKey()
	}

	msg1 := []byte("transaction 1")
	sig1, err := signer.Sign(msg1, ring, 0)
	require.NoError(t, err)

	// First verification and record should succeed
	err = VerifyAndRecord(sig1, msg1, ring, store)
	require.NoError(t, err)

	// Second transaction with same key should fail (double spend)
	msg2 := []byte("transaction 2")
	sig2, err := signer.Sign(msg2, ring, 0)
	require.NoError(t, err)

	err = VerifyAndRecord(sig2, msg2, ring, store)
	require.ErrorIs(t, err, ErrKeyImageReused)
}

func TestLSAGInvalidSignerIndex(t *testing.T) {
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		decoy, _ := NewSigner(LSAG)
		ring[i] = decoy.PublicKey()
	}

	message := []byte("test")

	// Signer's key is not in ring
	_, err = signer.Sign(message, ring, 0)
	require.Error(t, err)

	// Invalid index
	ring[1] = signer.PublicKey()
	_, err = signer.Sign(message, ring, -1)
	require.ErrorIs(t, err, ErrInvalidSignerIndex)

	_, err = signer.Sign(message, ring, 5)
	require.ErrorIs(t, err, ErrInvalidSignerIndex)
}

func TestLSAGTooSmallRing(t *testing.T) {
	signer, err := NewSigner(LSAG)
	require.NoError(t, err)

	// Ring of size 1 should fail
	ring := [][]byte{signer.PublicKey()}
	message := []byte("test")

	_, err = signer.Sign(message, ring, 0)
	require.ErrorIs(t, err, ErrInvalidRingSize)
}

func TestLatticeSignerCreation(t *testing.T) {
	signer, err := NewSigner(LatticeLSAG)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.Equal(t, LatticeLSAG, signer.Scheme())

	pubKey := signer.PublicKey()
	require.NotEmpty(t, pubKey)
	// ML-DSA-65 public key size
	require.Len(t, pubKey, 1952)

	keyImage := signer.KeyImage()
	require.NotEmpty(t, keyImage)
	// Key image is SHA-256 hash
	require.Len(t, keyImage, 32)
}

func TestLatticeSignAndVerify(t *testing.T) {
	// ML-DSA based ring signature test
	signer, err := NewSigner(LatticeLSAG)
	require.NoError(t, err)

	// Create ring with 3 members (smaller for faster tests with ML-DSA)
	ringSize := 3
	signerIndex := 1
	ring := make([][]byte, ringSize)

	for i := 0; i < ringSize; i++ {
		if i == signerIndex {
			ring[i] = signer.PublicKey()
		} else {
			decoy, err := NewSigner(LatticeLSAG)
			require.NoError(t, err)
			ring[i] = decoy.PublicKey()
		}
	}

	message := []byte("post-quantum ring signature test")
	sig, err := signer.Sign(message, ring, signerIndex)
	require.NoError(t, err)
	require.NotNil(t, sig)

	require.False(t, sig.Verify(message, ring),
		"LatticeLSAG must not verify while its construction is universally forgeable")
	require.Equal(t, ringSize, sig.RingSize())
	require.Equal(t, LatticeLSAG, sig.Scheme())

	// Key image should match signer's key image
	require.Equal(t, signer.KeyImage(), sig.KeyImage())
}

func TestLatticeSerialization(t *testing.T) {
	signer, err := NewSigner(LatticeLSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LatticeLSAG)
		ring[i] = decoy.PublicKey()
	}

	message := []byte("lattice serialization test")
	sig, err := signer.Sign(message, ring, 0)
	require.NoError(t, err)

	// Serialize
	data := sig.Bytes()
	require.NotEmpty(t, data)

	// Deserialize
	parsed, err := ParseSignature(LatticeLSAG, data)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Serialization round-trips; verification still refuses, because the
	// construction is forgeable rather than the encoding being wrong.
	require.False(t, parsed.Verify(message, ring),
		"LatticeLSAG must not verify while its construction is universally forgeable")
	require.Equal(t, sig.KeyImage(), parsed.KeyImage())
	require.Equal(t, sig.RingSize(), parsed.RingSize())
}

func TestLatticeKeyImageLinkability(t *testing.T) {
	// Create signer
	signer, err := NewSigner(LatticeLSAG)
	require.NoError(t, err)

	// Create ring
	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LatticeLSAG)
		ring[i] = decoy.PublicKey()
	}

	// Sign two different messages
	msg1 := []byte("message 1")
	msg2 := []byte("message 2")

	sig1, err := signer.Sign(msg1, ring, 0)
	require.NoError(t, err)

	sig2, err := signer.Sign(msg2, ring, 0)
	require.NoError(t, err)

	// Key images should be the same (linkable)
	require.Equal(t, sig1.KeyImage(), sig2.KeyImage(), "key images should match for same signer")

	// Different signer should have different key image
	otherSigner, _ := NewSigner(LatticeLSAG)
	otherRing := make([][]byte, 3)
	otherRing[0] = otherSigner.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LatticeLSAG)
		otherRing[i] = decoy.PublicKey()
	}

	sig3, err := otherSigner.Sign(msg1, otherRing, 0)
	require.NoError(t, err)

	require.NotEqual(t, sig1.KeyImage(), sig3.KeyImage(), "different signers should have different key images")
}

func TestLatticeSignatureInvalidMessage(t *testing.T) {
	signer, err := NewSigner(LatticeLSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LatticeLSAG)
		ring[i] = decoy.PublicKey()
	}

	message := []byte("original message")
	sig, err := signer.Sign(message, ring, 0)
	require.NoError(t, err)

	// Should fail with different message
	wrongMessage := []byte("wrong message")
	require.False(t, sig.Verify(wrongMessage, ring), "signature should not verify with wrong message")
}

func TestLatticeSignatureInvalidRing(t *testing.T) {
	signer, err := NewSigner(LatticeLSAG)
	require.NoError(t, err)

	ring := make([][]byte, 3)
	ring[0] = signer.PublicKey()
	for i := 1; i < 3; i++ {
		decoy, _ := NewSigner(LatticeLSAG)
		ring[i] = decoy.PublicKey()
	}

	message := []byte("test message")
	sig, err := signer.Sign(message, ring, 0)
	require.NoError(t, err)

	// Modify ring (replace a key)
	wrongRing := make([][]byte, len(ring))
	copy(wrongRing, ring)
	decoy, _ := NewSigner(LatticeLSAG)
	wrongRing[1] = decoy.PublicKey()

	require.False(t, sig.Verify(message, wrongRing), "signature should not verify with modified ring")
}

func TestGenerateRing(t *testing.T) {
	// LSAG ring
	ring, err := GenerateRing(LSAG, 5)
	require.NoError(t, err)
	require.Len(t, ring, 5)
	for _, pk := range ring {
		require.Len(t, pk, 33) // Compressed secp256k1 public key
	}

	// Lattice ring (ML-DSA-65 public keys)
	ring, err = GenerateRing(LatticeLSAG, 3)
	require.NoError(t, err)
	require.Len(t, ring, 3)
	for _, pk := range ring {
		require.Len(t, pk, 1952) // ML-DSA-65 public key size
	}

	// Invalid ring size
	_, err = GenerateRing(LSAG, 1)
	require.ErrorIs(t, err, ErrInvalidRingSize)
}

func TestLSAGDifferentRingSizes(t *testing.T) {
	testCases := []int{2, 3, 5, 10, 20}

	for _, ringSize := range testCases {
		t.Run("", func(t *testing.T) {
			signer, err := NewSigner(LSAG)
			require.NoError(t, err)

			signerIndex := ringSize / 2
			ring := make([][]byte, ringSize)
			for i := 0; i < ringSize; i++ {
				if i == signerIndex {
					ring[i] = signer.PublicKey()
				} else {
					decoy, _ := NewSigner(LSAG)
					ring[i] = decoy.PublicKey()
				}
			}

			message := []byte("ring size test")
			sig, err := signer.Sign(message, ring, signerIndex)
			require.NoError(t, err)
			require.True(t, sig.Verify(message, ring))
		})
	}
}

func BenchmarkLSAGSign(b *testing.B) {
	signer, _ := NewSigner(LSAG)

	ring := make([][]byte, 10)
	ring[5] = signer.PublicKey()
	for i := 0; i < 10; i++ {
		if i != 5 {
			decoy, _ := NewSigner(LSAG)
			ring[i] = decoy.PublicKey()
		}
	}

	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(message, ring, 5)
	}
}

func BenchmarkLSAGVerify(b *testing.B) {
	signer, _ := NewSigner(LSAG)

	ring := make([][]byte, 10)
	ring[5] = signer.PublicKey()
	for i := 0; i < 10; i++ {
		if i != 5 {
			decoy, _ := NewSigner(LSAG)
			ring[i] = decoy.PublicKey()
		}
	}

	message := []byte("benchmark message")
	sig, _ := signer.Sign(message, ring, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig.Verify(message, ring)
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}
	d := []byte{1, 2, 3}

	require.True(t, constantTimeCompare(a, b))
	require.False(t, constantTimeCompare(a, c))
	require.False(t, constantTimeCompare(a, d))
	require.True(t, bytes.Equal(a, b))
}
