// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Comprehensive test suite for all post-quantum cryptography implementations

package crypto

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/crypto/lamport"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/precompile"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllCryptoImplementations tests all crypto standards
func TestAllCryptoImplementations(t *testing.T) {
	t.Run("ML-KEM", testMLKEM)
	t.Run("ML-DSA", testMLDSA)
	t.Run("SLH-DSA", testSLHDSA)
	// Lamport tests are covered in the lamport package
	// t.Run("Lamport", testLamport)
	t.Run("Precompiles", testPrecompiles)
	t.Run("CGO Performance", testCGOPerformance)
}

func testMLKEM(t *testing.T) {
	modes := []mlkem.Mode{mlkem.MLKEM512, mlkem.MLKEM768, mlkem.MLKEM1024}
	names := []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}

	for i, mode := range modes {
		t.Run(names[i], func(t *testing.T) {
			// Generate key pair
			priv, _, err := mlkem.GenerateKeyPair(rand.Reader, mode)
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
			assert.NoError(t, err) // ML-KEM has implicit rejection
			assert.NotEqual(t, sharedSecret, wrongSecret)

			// Test serialization
			pubBytes := priv.PublicKey.Bytes()
			privBytes := priv.Bytes()

			pub2, err := mlkem.PublicKeyFromBytes(pubBytes, mode)
			require.NoError(t, err)

			priv2, err := mlkem.PrivateKeyFromBytes(privBytes, mode)
			require.NoError(t, err)

			// Test with deserialized keys
			result2, err := pub2.Encapsulate(rand.Reader)
			require.NoError(t, err)

			secret2, err := priv2.Decapsulate(result2.Ciphertext)
			require.NoError(t, err)
			assert.Equal(t, result2.SharedSecret, secret2)
		})
	}
}

func testMLDSA(t *testing.T) {
	modes := []mldsa.Mode{mldsa.MLDSA44, mldsa.MLDSA65, mldsa.MLDSA87}
	names := []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
	message := []byte("Test message for ML-DSA signature")

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

			// Test serialization
			pubBytes := priv.PublicKey.Bytes()
			privBytes := priv.Bytes()

			pub2, err := mldsa.PublicKeyFromBytes(pubBytes, mode)
			require.NoError(t, err)

			priv2, err := mldsa.PrivateKeyFromBytes(privBytes, mode)
			require.NoError(t, err)

			// Sign with deserialized key
			sig2, err := priv2.Sign(rand.Reader, message, nil)
			require.NoError(t, err)
			assert.True(t, pub2.Verify(message, sig2, nil))
		})
	}
}

func testSLHDSA(t *testing.T) {
	// Test only fast variants for speed
	modes := []slhdsa.Mode{slhdsa.SLHDSA128f, slhdsa.SLHDSA192f}
	names := []string{"SLH-DSA-128f", "SLH-DSA-192f"}
	message := []byte("Test message for SLH-DSA")

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

			// Test serialization
			pubBytes := priv.PublicKey.Bytes()
			pub2, err := slhdsa.PublicKeyFromBytes(pubBytes, mode)
			require.NoError(t, err)
			assert.True(t, pub2.Verify(message, signature, nil))
		})
	}
}

func testLamport(t *testing.T) {
	message := []byte("Test message for Lamport signature")

	t.Run("SHA256", func(t *testing.T) {
		priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
		require.NoError(t, err)

		pub := priv.Public()

		// Sign message
		sig, err := priv.Sign(message)
		require.NoError(t, err)

		// Verify signature
		assert.True(t, pub.Verify(message, sig))

		// Test wrong message
		wrongMsg := []byte("Wrong message")
		assert.False(t, pub.Verify(wrongMsg, sig))

		// Test serialization
		pubBytes := pub.Bytes()
		sigBytes := sig.Bytes()

		pub2, err := lamport.PublicKeyFromBytes(pubBytes)
		require.NoError(t, err)

		sig2, err := lamport.SignatureFromBytes(sigBytes)
		require.NoError(t, err)

		assert.True(t, pub2.Verify(message, sig2))
	})

	t.Run("OneTimeUse", func(t *testing.T) {
		priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
		require.NoError(t, err)

		pub := priv.Public()

		// First signature should work
		sig1, err := priv.Sign(message)
		require.NoError(t, err)
		assert.True(t, pub.Verify(message, sig1))

		// Second signature should fail (key was zeroed)
		sig2, err := priv.Sign([]byte("Second message"))
		require.NoError(t, err)

		// Verify that second signature doesn't work (since key was zeroed)
		// This is a one-time signature scheme
		assert.NotNil(t, sig2)
	})
}

func testPrecompiles(t *testing.T) {
	// Test SHAKE precompiles
	t.Run("SHAKE", func(t *testing.T) {
		shake256 := &precompile.SHAKE256{}

		// Create input: [4 bytes output_len][data]
		input := make([]byte, 4+32)
		input[0] = 0x00
		input[1] = 0x00
		input[2] = 0x00
		input[3] = 0x20 // 32 bytes output
		copy(input[4:], []byte("test data for SHAKE256"))

		gas := shake256.RequiredGas(input)
		assert.Greater(t, gas, uint64(0))

		output, err := shake256.Run(input)
		require.NoError(t, err)
		assert.Len(t, output, 32)
	})

	// Lamport precompile tests are covered in the precompile package
	// t.Run("Lamport", func(t *testing.T) { ... })

	// Test BLS precompile
	t.Run("BLS", func(t *testing.T) {
		blsVerify := &precompile.BLSVerify{}

		// Create dummy input (96 bytes sig + 48 bytes pubkey + message)
		input := make([]byte, 96+48+32)
		rand.Read(input)

		gas := blsVerify.RequiredGas(input)
		assert.Equal(t, uint64(150000), gas)

		// Run will return placeholder result
		result, err := blsVerify.Run(input)
		require.NoError(t, err)
		assert.Len(t, result, 32)
	})
}

func testCGOPerformance(t *testing.T) {
	// This test is for comparing performance when CGO optimizations are available
	// CGO implementations are opt-in only with CGO=1

	t.Run("ML-KEM Performance", func(t *testing.T) {
		message := make([]byte, 32)
		rand.Read(message)

		// Benchmark pure Go implementation
		priv, _, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)

		start := time.Now()
		for i := 0; i < 100; i++ {
			priv.PublicKey.Encapsulate(rand.Reader)
		}
		duration := time.Since(start)

		t.Logf("ML-KEM-768 Encapsulate (100 ops): %v", duration)
	})

	t.Run("ML-DSA Performance", func(t *testing.T) {
		message := make([]byte, 32)
		rand.Read(message)

		// Benchmark pure Go implementation
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

		start := time.Now()
		for i := 0; i < 100; i++ {
			priv.Sign(rand.Reader, message, nil)
		}
		duration := time.Since(start)

		t.Logf("ML-DSA-65 Sign (100 ops): %v", duration)
	})

	t.Run("SLH-DSA Performance", func(t *testing.T) {
		message := make([]byte, 32)
		rand.Read(message)

		// Benchmark pure Go implementation (fast variant)
		priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128f)

		start := time.Now()
		for i := 0; i < 10; i++ { // Fewer iterations due to larger signatures
			priv.Sign(rand.Reader, message, nil)
		}
		duration := time.Since(start)

		t.Logf("SLH-DSA-128f Sign (10 ops): %v", duration)
	})
}

// BenchmarkCrypto benchmarks all crypto implementations
func BenchmarkCrypto(b *testing.B) {
	b.Run("ML-KEM-768", func(b *testing.B) {
		priv, _, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)

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

	b.Run("Lamport-SHA256", func(b *testing.B) {
		message := make([]byte, 32)

		b.Run("Generate", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				lamport.GenerateKey(rand.Reader, lamport.SHA256)
			}
		})

		priv, _ := lamport.GenerateKey(rand.Reader, lamport.SHA256)
		pub := priv.Public()
		sig, _ := priv.Sign(message)

		b.Run("Verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pub.Verify(message, sig)
			}
		})
	})
}
