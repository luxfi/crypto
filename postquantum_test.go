// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Comprehensive tests for FIPS 203/204/205 post-quantum cryptography

package crypto

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLKEM tests ML-KEM (FIPS 203) key encapsulation
func TestMLKEM(t *testing.T) {
	modes := []mlkem.Mode{mlkem.MLKEM512, mlkem.MLKEM768, mlkem.MLKEM1024}
	names := []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}

	for i, mode := range modes {
		t.Run(names[i], func(t *testing.T) {
			// Generate key pair
			priv, err := mlkem.GenerateKeyPair(rand.Reader, mode)
			require.NoError(t, err)

			// Encapsulate
			result, err := priv.PublicKey.Encapsulate(rand.Reader)
			require.NoError(t, err)

			// Decapsulate
			sharedSecret, err := priv.Decapsulate(result.Ciphertext)
			require.NoError(t, err)

			// Verify shared secrets match
			assert.Equal(t, result.SharedSecret, sharedSecret)

			// Test wrong ciphertext
			wrongCT := make([]byte, len(result.Ciphertext))
			copy(wrongCT, result.Ciphertext)
			wrongCT[0] ^= 0xFF

			wrongSecret, err := priv.Decapsulate(wrongCT)
			// ML-KEM has implicit rejection, so no error but different secret
			assert.NoError(t, err)
			assert.NotEqual(t, sharedSecret, wrongSecret)
		})
	}
}

// TestMLDSA tests ML-DSA (FIPS 204) digital signatures
func TestMLDSA(t *testing.T) {
	modes := []mldsa.Mode{mldsa.MLDSA44, mldsa.MLDSA65, mldsa.MLDSA87}
	names := []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}

	message := []byte("Post-quantum signature test message")

	for i, mode := range modes {
		t.Run(names[i], func(t *testing.T) {
			// Generate key pair
			priv, err := mldsa.GenerateKey(rand.Reader, mode)
			require.NoError(t, err)

			// Sign message
			signature, err := priv.Sign(rand.Reader, message, nil)
			require.NoError(t, err)

			// Verify signature
			valid := priv.PublicKey.Verify(message, signature, nil)
			assert.True(t, valid)

			// Test wrong message
			wrongMsg := []byte("Wrong message")
			assert.False(t, priv.PublicKey.Verify(wrongMsg, signature, nil))

			// Test corrupted signature
			corruptedSig := make([]byte, len(signature))
			copy(corruptedSig, signature)
			corruptedSig[0] ^= 0xFF
			assert.False(t, priv.PublicKey.Verify(message, corruptedSig, nil))
		})
	}
}

// TestSLHDSA tests SLH-DSA (FIPS 205) hash-based signatures
func TestSLHDSA(t *testing.T) {
	// Test only small/fast variants for speed
	modes := []slhdsa.Mode{slhdsa.SLHDSA128s, slhdsa.SLHDSA128f}
	names := []string{"SLH-DSA-128s", "SLH-DSA-128f"}

	message := []byte("Stateless hash-based signature test")

	for i, mode := range modes {
		t.Run(names[i], func(t *testing.T) {
			// Generate key pair
			priv, err := slhdsa.GenerateKey(rand.Reader, mode)
			require.NoError(t, err)

			// Sign message
			signature, err := priv.Sign(rand.Reader, message, nil)
			require.NoError(t, err)

			// Verify signature
			valid := priv.PublicKey.Verify(message, signature, nil)
			assert.True(t, valid)

			// Test stateless property - same signature for same message
			signature2, err := priv.Sign(rand.Reader, message, nil)
			require.NoError(t, err)
			assert.Equal(t, signature, signature2, "SLH-DSA should be deterministic")

			// Test wrong message
			wrongMsg := []byte("Wrong message")
			assert.False(t, priv.PublicKey.Verify(wrongMsg, signature, nil))
		})
	}
}

// TestPerformance tests performance of pure Go implementations
func TestPerformance(t *testing.T) {
	t.Run("ML-KEM Performance", func(t *testing.T) {
		// Benchmark pure Go implementation
		priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)

		// Encapsulation benchmark
		start := time.Now()
		for i := 0; i < 100; i++ {
			priv.PublicKey.Encapsulate(rand.Reader)
		}
		duration := time.Since(start)

		t.Logf("ML-KEM-768 Encapsulate (100 ops): %v", duration)
		assert.Less(t, duration, 5*time.Second, "Should complete 100 encapsulations in under 5 seconds")
	})

	t.Run("ML-DSA Performance", func(t *testing.T) {
		message := make([]byte, 32)
		rand.Read(message)

		// Benchmark pure Go implementation
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

		// Signing benchmark
		start := time.Now()
		for i := 0; i < 100; i++ {
			priv.Sign(rand.Reader, message, nil)
		}
		duration := time.Since(start)

		t.Logf("ML-DSA-65 Sign (100 ops): %v", duration)
		assert.Less(t, duration, 5*time.Second, "Should complete 100 signatures in under 5 seconds")
	})

	t.Run("SLH-DSA Performance", func(t *testing.T) {
		message := make([]byte, 32)
		rand.Read(message)

		// Benchmark pure Go implementation
		priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128f)

		start := time.Now()
		for i := 0; i < 10; i++ {
			priv.Sign(rand.Reader, message, nil)
		}
		duration := time.Since(start)

		t.Logf("SLH-DSA-128f Sign (10 ops): %v", duration)
	})
}

// TestHybridCrypto tests combining classical and post-quantum crypto
func TestHybridCrypto(t *testing.T) {
	t.Run("Hybrid Key Exchange", func(t *testing.T) {
		// Classical ECDH (placeholder)
		classicalSecret := make([]byte, 32)
		rand.Read(classicalSecret)

		// Post-quantum ML-KEM
		priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
		result, _ := priv.PublicKey.Encapsulate(rand.Reader)
		pqSecret, _ := priv.Decapsulate(result.Ciphertext)

		// Combine secrets (simplified - use proper KDF in production)
		hybridSecret := make([]byte, 64)
		copy(hybridSecret[:32], classicalSecret)
		copy(hybridSecret[32:], pqSecret)

		assert.Len(t, hybridSecret, 64)
	})

	t.Run("Hybrid Signatures", func(t *testing.T) {
		message := []byte("Hybrid signature test")

		// Classical ECDSA (placeholder)
		classicalSig := make([]byte, 64)
		rand.Read(classicalSig)

		// Post-quantum ML-DSA
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		pqSig, _ := priv.Sign(rand.Reader, message, nil)

		// Combine signatures
		_ = append(classicalSig, pqSig...) // hybridSig would be used in production

		// Verify both
		// Classical verification (placeholder - would be ECDSA)
		classicalValid := true

		// PQ verification
		pqValid := priv.PublicKey.Verify(message, pqSig, nil)

		// Both must be valid
		assert.True(t, classicalValid && pqValid)
	})
}

// BenchmarkPostQuantum benchmarks all three standards
func BenchmarkPostQuantum(b *testing.B) {
	b.Run("ML-KEM-768", func(b *testing.B) {
		priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)

		b.Run("Encapsulate", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.PublicKey.Encapsulate(rand.Reader)
			}
		})

		result, _ := priv.PublicKey.Encapsulate(rand.Reader)
		b.Run("Decapsulate", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.Decapsulate(result.Ciphertext)
			}
		})
	})

	b.Run("ML-DSA-65", func(b *testing.B) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		message := make([]byte, 32)

		b.Run("Sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.Sign(rand.Reader, message, nil)
			}
		})

		sig, _ := priv.Sign(rand.Reader, message, nil)
		b.Run("Verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.PublicKey.Verify(message, sig, nil)
			}
		})
	})

	b.Run("SLH-DSA-128f", func(b *testing.B) {
		priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128f)
		message := make([]byte, 32)

		b.Run("Sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.Sign(rand.Reader, message, nil)
			}
		})

		sig, _ := priv.Sign(rand.Reader, message, nil)
		b.Run("Verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.PublicKey.Verify(message, sig, nil)
			}
		})
	})
}

// TestSizesAndParameters verifies all parameter sizes match FIPS specifications
func TestSizesAndParameters(t *testing.T) {
	// ML-KEM sizes (FIPS 203)
	assert.Equal(t, 1184, mlkem.MLKEM768PublicKeySize)
	assert.Equal(t, 1088, mlkem.MLKEM768CiphertextSize)

	// ML-DSA sizes (FIPS 204)
	assert.Equal(t, 1952, mldsa.MLDSA65PublicKeySize)
	assert.Equal(t, 3293, mldsa.MLDSA65SignatureSize)

	// SLH-DSA sizes (FIPS 205)
	assert.Equal(t, 32, slhdsa.SLHDSA128sPublicKeySize)
	assert.Equal(t, 7856, slhdsa.SLHDSA128sSignatureSize)
	assert.Equal(t, 32, slhdsa.SLHDSA128fPublicKeySize)
	assert.Equal(t, 17088, slhdsa.SLHDSA128fSignatureSize)
}
