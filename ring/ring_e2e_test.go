// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/ring"
	"github.com/stretchr/testify/require"
)

// TestE2E_LSAGRingSignature tests the complete LSAG ring signature flow
func TestE2E_LSAGRingSignature(t *testing.T) {
	const ringSize = 5
	const signerIndex = 2

	// Step 1: Create signers (simulating key generation)
	signers := make([]ring.Signer, ringSize)
	for i := 0; i < ringSize; i++ {
		signer, err := ring.NewSigner(ring.LSAG)
		require.NoError(t, err)
		signers[i] = signer
	}

	// Step 2: Build the ring of public keys
	ringPubKeys := make([][]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		ringPubKeys[i] = signers[i].PublicKey()
	}

	// Step 3: Sign a message
	message := []byte("This is a confidential transaction on Q-Chain")
	sig, err := signers[signerIndex].Sign(message, ringPubKeys, signerIndex)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Step 4: Verify the signature
	valid := sig.Verify(message, ringPubKeys)
	require.True(t, valid, "signature should be valid")

	// Step 5: Verify key image linkability
	keyImage := sig.KeyImage()
	require.NotEmpty(t, keyImage)

	// Same signer should produce the same key image
	signerKeyImage := signers[signerIndex].KeyImage()
	require.True(t, bytes.Equal(keyImage, signerKeyImage), "key images should match")

	// Step 6: Verify serialization/deserialization
	sigBytes := sig.Bytes()
	parsedSig, err := ring.ParseSignature(ring.LSAG, sigBytes)
	require.NoError(t, err)
	require.True(t, parsedSig.Verify(message, ringPubKeys), "parsed signature should verify")

	// Step 7: Verify wrong message fails
	wrongMessage := []byte("This is a different message")
	require.False(t, sig.Verify(wrongMessage, ringPubKeys), "wrong message should fail")

	// Step 8: Verify different key produces different key image
	otherKeyImage := signers[0].KeyImage()
	require.False(t, bytes.Equal(keyImage, otherKeyImage), "different signers should have different key images")

	t.Logf("LSAG E2E test passed: ring size=%d, signature size=%d bytes, key image=%x...",
		ringSize, len(sigBytes), keyImage[:8])
}

// TestE2E_LatticeRingSignature tests the complete lattice ring signature flow
func TestE2E_LatticeRingSignature(t *testing.T) {
	const ringSize = 3
	const signerIndex = 1

	// Step 1: Create lattice signers (post-quantum)
	signers := make([]ring.Signer, ringSize)
	for i := 0; i < ringSize; i++ {
		signer, err := ring.NewSigner(ring.LatticeLSAG)
		require.NoError(t, err)
		signers[i] = signer
	}

	// Step 2: Build the ring of public keys
	ringPubKeys := make([][]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		ringPubKeys[i] = signers[i].PublicKey()
	}

	// Step 3: Sign a message
	message := []byte("Post-quantum secure anonymous transaction")
	sig, err := signers[signerIndex].Sign(message, ringPubKeys, signerIndex)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Step 4: Verify the signature
	valid := sig.Verify(message, ringPubKeys)
	require.True(t, valid, "signature should be valid")

	// Step 5: Verify key image linkability
	keyImage := sig.KeyImage()
	signerKeyImage := signers[signerIndex].KeyImage()
	require.True(t, bytes.Equal(keyImage, signerKeyImage), "key images should match")

	// Step 6: Verify serialization
	sigBytes := sig.Bytes()
	parsedSig, err := ring.ParseSignature(ring.LatticeLSAG, sigBytes)
	require.NoError(t, err)
	require.True(t, parsedSig.Verify(message, ringPubKeys), "parsed signature should verify")

	t.Logf("Lattice E2E test passed: ring size=%d, signature size=%d bytes, key image=%x...",
		ringSize, len(sigBytes), keyImage[:8])
}

// TestE2E_MultipleSignaturesSameKey tests double-spend detection via key images
func TestE2E_MultipleSignaturesSameKey(t *testing.T) {
	const ringSize = 4
	const signerIndex = 1

	// Create signers
	signers := make([]ring.Signer, ringSize)
	for i := 0; i < ringSize; i++ {
		signer, err := ring.NewSigner(ring.LSAG)
		require.NoError(t, err)
		signers[i] = signer
	}

	// Build ring
	ringPubKeys := make([][]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		ringPubKeys[i] = signers[i].PublicKey()
	}

	// Sign two different messages with the same key
	message1 := []byte("Transaction 1: Transfer 100 LUX")
	message2 := []byte("Transaction 2: Transfer 50 LUX")

	sig1, err := signers[signerIndex].Sign(message1, ringPubKeys, signerIndex)
	require.NoError(t, err)

	sig2, err := signers[signerIndex].Sign(message2, ringPubKeys, signerIndex)
	require.NoError(t, err)

	// Both signatures should be valid
	require.True(t, sig1.Verify(message1, ringPubKeys))
	require.True(t, sig2.Verify(message2, ringPubKeys))

	// KEY IMAGE SHOULD BE THE SAME - this enables double-spend detection
	require.True(t, bytes.Equal(sig1.KeyImage(), sig2.KeyImage()),
		"key images should match for same signer - enables double-spend detection")

	// Use KeyImageStore for double-spend detection
	store := ring.NewMemoryKeyImageStore()

	// First signature should be accepted
	err = ring.VerifyAndRecord(sig1, message1, ringPubKeys, store)
	require.NoError(t, err)

	// Second signature from same key should be REJECTED (double-spend)
	err = ring.VerifyAndRecord(sig2, message2, ringPubKeys, store)
	require.Error(t, err)
	require.Equal(t, ring.ErrKeyImageReused, err, "should detect double-spend via key image")

	t.Log("Double-spend detection E2E test passed")
}

// TestE2E_DifferentRingSizes tests ring signatures with various ring sizes
func TestE2E_DifferentRingSizes(t *testing.T) {
	sizes := []int{2, 3, 5, 10, 20}

	for _, size := range sizes {
		t.Run(string(rune('0'+size/10))+string(rune('0'+size%10))+"_members", func(t *testing.T) {
			// Create ring
			signers := make([]ring.Signer, size)
			ringPubKeys := make([][]byte, size)
			for i := 0; i < size; i++ {
				signer, err := ring.NewSigner(ring.LSAG)
				require.NoError(t, err)
				signers[i] = signer
				ringPubKeys[i] = signer.PublicKey()
			}

			// Pick a random signer
			signerIndex := 0
			if size > 1 {
				buf := make([]byte, 1)
				rand.Read(buf)
				signerIndex = int(buf[0]) % size
			}

			// Sign and verify
			message := []byte("test message for ring size " + string(rune('0'+size/10)) + string(rune('0'+size%10)))
			sig, err := signers[signerIndex].Sign(message, ringPubKeys, signerIndex)
			require.NoError(t, err)

			valid := sig.Verify(message, ringPubKeys)
			require.True(t, valid, "ring size %d should work", size)

			t.Logf("Ring size %d: signature %d bytes", size, len(sig.Bytes()))
		})
	}
}

// TestE2E_CrossSchemeIsolation ensures different schemes don't interfere
func TestE2E_CrossSchemeIsolation(t *testing.T) {
	// Create LSAG ring
	lsagSigner, err := ring.NewSigner(ring.LSAG)
	require.NoError(t, err)

	lsagRing := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		s, _ := ring.NewSigner(ring.LSAG)
		if i == 0 {
			lsagRing[i] = lsagSigner.PublicKey()
		} else {
			lsagRing[i] = s.PublicKey()
		}
	}

	// Create Lattice ring
	latticeSigner, err := ring.NewSigner(ring.LatticeLSAG)
	require.NoError(t, err)

	latticeRing := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		s, _ := ring.NewSigner(ring.LatticeLSAG)
		if i == 0 {
			latticeRing[i] = latticeSigner.PublicKey()
		} else {
			latticeRing[i] = s.PublicKey()
		}
	}

	message := []byte("test isolation")

	// Sign with each scheme
	lsagSig, err := lsagSigner.Sign(message, lsagRing, 0)
	require.NoError(t, err)

	latticeSig, err := latticeSigner.Sign(message, latticeRing, 0)
	require.NoError(t, err)

	// Verify each with correct ring
	require.True(t, lsagSig.Verify(message, lsagRing))
	require.True(t, latticeSig.Verify(message, latticeRing))

	// Verify LSAG doesn't verify with lattice ring and vice versa
	require.False(t, lsagSig.Verify(message, latticeRing), "LSAG should not verify with lattice ring")
	require.False(t, latticeSig.Verify(message, lsagRing), "Lattice should not verify with LSAG ring")

	t.Log("Cross-scheme isolation test passed")
}

// BenchmarkLSAGSignVerify benchmarks LSAG operations
func BenchmarkLSAGSignVerify(b *testing.B) {
	signer, _ := ring.NewSigner(ring.LSAG)
	ring5, _ := ring.GenerateRing(ring.LSAG, 5)
	ring5[0] = signer.PublicKey()
	message := []byte("benchmark message")

	b.Run("Sign_5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signer.Sign(message, ring5, 0)
		}
	})

	sig, _ := signer.Sign(message, ring5, 0)

	b.Run("Verify_5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sig.Verify(message, ring5)
		}
	})
}

// BenchmarkLatticeSignVerify benchmarks Lattice operations
func BenchmarkLatticeSignVerify(b *testing.B) {
	signer, _ := ring.NewSigner(ring.LatticeLSAG)
	ring3, _ := ring.GenerateRing(ring.LatticeLSAG, 3)
	ring3[0] = signer.PublicKey()
	message := []byte("benchmark message")

	b.Run("Sign_3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signer.Sign(message, ring3, 0)
		}
	})

	sig, _ := signer.Sign(message, ring3, 0)

	b.Run("Verify_3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sig.Verify(message, ring3)
		}
	})
}
