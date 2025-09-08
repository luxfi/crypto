// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Post-Quantum Cryptography Integration Tests

package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/stretchr/testify/require"
)

// TestMLDSAIntegration tests ML-DSA digital signatures
func TestMLDSAIntegration(t *testing.T) {
	require := require.New(t)

	modes := []mldsa.Mode{
		mldsa.MLDSA44,
		mldsa.MLDSA65,
		mldsa.MLDSA87,
	}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			// Generate key pair
			priv, err := mldsa.GenerateKey(rand.Reader, mode)
			require.NoError(err)
			require.NotNil(priv)

			// Test message
			message := []byte("Post-Quantum Digital Signature Test Message")

			// Sign message
			signature, err := priv.Sign(rand.Reader, message, nil)
			require.NoError(err)
			require.NotEmpty(signature)

			// Verify signature
			valid := priv.PublicKey.Verify(message, signature, nil)
			require.True(valid, "Signature should be valid")

			// Test invalid signature
			signature[0] ^= 0xFF
			valid = priv.PublicKey.Verify(message, signature, nil)
			require.False(valid, "Modified signature should be invalid")
		})
	}
}

// TestMLKEMIntegration tests ML-KEM key encapsulation
func TestMLKEMIntegration(t *testing.T) {
	require := require.New(t)

	modes := []mlkem.Mode{
		mlkem.MLKEM512,
		mlkem.MLKEM768,
		mlkem.MLKEM1024,
	}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			// Generate key pair
			priv, pub, err := mlkem.GenerateKeyPair(rand.Reader, mode)
			require.NoError(err)
			require.NotNil(priv)
			require.NotNil(pub)

			// Encapsulate
			ciphertext, sharedSecret, err := pub.Encapsulate(rand.Reader)
			require.NoError(err)
			require.NotEmpty(ciphertext)
			require.NotEmpty(sharedSecret)

			// Decapsulate
			sharedSecret2, err := priv.Decapsulate(ciphertext)
			require.NoError(err)
			require.Equal(sharedSecret, sharedSecret2)

			// Test serialization
			pubBytes := pub.Bytes()
			require.NotEmpty(pubBytes)

			privBytes := priv.Bytes()
			require.NotEmpty(privBytes)
		})
	}
}

// TestSLHDSAIntegration tests SLH-DSA hash-based signatures
func TestSLHDSAIntegration(t *testing.T) {
	require := require.New(t)

	modes := []slhdsa.Mode{
		slhdsa.SLHDSA128s,
		slhdsa.SLHDSA192s,
		slhdsa.SLHDSA256s,
	}

	for _, mode := range modes {
		t.Run(fmt.Sprintf("Mode%d", mode), func(t *testing.T) {
			// Generate key pair
			priv, err := slhdsa.GenerateKey(rand.Reader, mode)
			require.NoError(err)
			require.NotNil(priv)

			// Test message
			message := []byte("Stateless Hash-based Signature Test")

			// Sign message
			signature, err := priv.Sign(rand.Reader, message, nil)
			require.NoError(err)
			require.NotEmpty(signature)

			// Verify signature
			valid := priv.PublicKey.Verify(message, signature, nil)
			require.True(valid, "Signature should be valid")

			// Test invalid signature
			signature[0] ^= 0xFF
			valid = priv.PublicKey.Verify(message, signature, nil)
			require.False(valid, "Modified signature should be invalid")
		})
	}
}

// TestHybridCrypto tests hybrid classical + PQ modes
func TestHybridCrypto(t *testing.T) {
	require := require.New(t)

	// Test hybrid signing (classical + PQ)
	t.Run("HybridSigning", func(t *testing.T) {
		// Generate classical key (secp256k1)
		classicalPriv, err := GenerateKey()
		require.NoError(err)

		// Generate PQ key (ML-DSA)
		pqPriv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
		require.NoError(err)

		message := []byte("Hybrid signature test message")

		// Classical signature
		hash := Keccak256Hash(message)
		classicalSig, err := Sign(hash.Bytes(), classicalPriv)
		require.NoError(err)

		// PQ signature
		pqSig, err := pqPriv.Sign(rand.Reader, message, nil)
		require.NoError(err)

		// Verify both
		classicalPub := &classicalPriv.PublicKey
		require.True(VerifySignature(FromECDSAPub(classicalPub), hash.Bytes(), classicalSig[:64]))
		require.True(pqPriv.PublicKey.Verify(message, pqSig, nil))
	})
}

// BenchmarkPQCrypto benchmarks PQ operations
func BenchmarkPQCrypto(b *testing.B) {
	b.Run("ML-DSA-44-Sign", func(b *testing.B) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
		message := []byte("benchmark message")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = priv.Sign(rand.Reader, message, nil)
		}
	})

	b.Run("ML-KEM-512-Encapsulate", func(b *testing.B) {
		_, pub, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM512)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, _ = pub.Encapsulate(rand.Reader)
		}
	})

	b.Run("SLH-DSA-128s-Sign", func(b *testing.B) {
		priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128s)
		message := []byte("benchmark message")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = priv.Sign(rand.Reader, message, nil)
		}
	})
}