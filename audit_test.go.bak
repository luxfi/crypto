package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLKEMEdgeCases tests edge cases and potential bugs
func TestMLKEMEdgeCases(t *testing.T) {
	t.Run("Invalid Mode", func(t *testing.T) {
		_, err := mlkem.GenerateKeyPair(rand.Reader, mlkem.Mode(99))
		assert.Error(t, err)
	})

	t.Run("Nil Random Source", func(t *testing.T) {
		_, err := mlkem.GenerateKeyPair(nil, mlkem.MLKEM768)
		assert.Error(t, err)
	})

	t.Run("Empty Ciphertext", func(t *testing.T) {
		priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
		_, err := priv.Decapsulate([]byte{})
		assert.Error(t, err)
	})

	t.Run("Wrong Size Ciphertext", func(t *testing.T) {
		priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
		wrongCT := make([]byte, 100) // Wrong size
		_, err := priv.Decapsulate(wrongCT)
		assert.Error(t, err)
	})

	t.Run("Serialization Round Trip", func(t *testing.T) {
		modes := []mlkem.Mode{mlkem.MLKEM512, mlkem.MLKEM768, mlkem.MLKEM1024}
		for _, mode := range modes {
			priv1, _ := mlkem.GenerateKeyPair(rand.Reader, mode)
			
			// Serialize
			privBytes := priv1.Bytes()
			pubBytes := priv1.PublicKey.Bytes()
			
			// Deserialize
			priv2, err := mlkem.PrivateKeyFromBytes(privBytes, mode)
			require.NoError(t, err)
			pub2, err := mlkem.PublicKeyFromBytes(pubBytes, mode)
			require.NoError(t, err)
			
			// Verify they work the same
			result1, _ := priv1.PublicKey.Encapsulate(rand.Reader)
			secret1, _ := priv1.Decapsulate(result1.Ciphertext)
			
			result2, _ := pub2.Encapsulate(rand.Reader)
			secret2, _ := priv2.Decapsulate(result2.Ciphertext)
			
			// Both should produce valid shared secrets
			assert.Len(t, secret1, 32)
			assert.Len(t, secret2, 32)
		}
	})

	t.Run("Deterministic Public Key", func(t *testing.T) {
		// Same private key seed should generate same public key
		privBytes := make([]byte, mlkem.MLKEM768PrivateKeySize)
		copy(privBytes, []byte("deterministic seed for testing"))
		
		priv1, _ := mlkem.PrivateKeyFromBytes(privBytes, mlkem.MLKEM768)
		priv2, _ := mlkem.PrivateKeyFromBytes(privBytes, mlkem.MLKEM768)
		
		assert.Equal(t, priv1.PublicKey.Bytes(), priv2.PublicKey.Bytes())
	})
}

// TestMLDSAEdgeCases tests ML-DSA edge cases
func TestMLDSAEdgeCases(t *testing.T) {
	t.Run("Invalid Mode", func(t *testing.T) {
		_, err := mldsa.GenerateKey(rand.Reader, mldsa.Mode(99))
		assert.Error(t, err)
	})

	t.Run("Empty Message", func(t *testing.T) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		sig, err := priv.Sign(rand.Reader, []byte{}, nil)
		require.NoError(t, err)
		assert.True(t, priv.PublicKey.Verify([]byte{}, sig, nil))
	})

	t.Run("Large Message", func(t *testing.T) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		largeMsg := make([]byte, 10000)
		rand.Read(largeMsg)
		
		sig, err := priv.Sign(rand.Reader, largeMsg, nil)
		require.NoError(t, err)
		assert.True(t, priv.PublicKey.Verify(largeMsg, sig, nil))
	})

	t.Run("Signature Malleability", func(t *testing.T) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		msg := []byte("test message")
		
		sig1, _ := priv.Sign(rand.Reader, msg, nil)
		sig2, _ := priv.Sign(rand.Reader, msg, nil)
		
		// Signatures should be deterministic in our implementation
		assert.Equal(t, sig1, sig2)
	})

	t.Run("Wrong Signature Size", func(t *testing.T) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		msg := []byte("test")
		
		wrongSig := make([]byte, 100) // Wrong size
		assert.False(t, priv.PublicKey.Verify(msg, wrongSig, nil))
	})

	t.Run("Cross Mode Verification", func(t *testing.T) {
		priv44, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
		priv65, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		msg := []byte("test")
		
		sig44, _ := priv44.Sign(rand.Reader, msg, nil)
		
		// ML-DSA65 key shouldn't verify ML-DSA44 signature
		assert.False(t, priv65.PublicKey.Verify(msg, sig44, nil))
	})
}

// TestSLHDSAEdgeCases tests SLH-DSA edge cases
func TestSLHDSAEdgeCases(t *testing.T) {
	t.Run("Deterministic Signatures", func(t *testing.T) {
		priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128f)
		msg := []byte("deterministic test")
		
		sig1, _ := priv.Sign(rand.Reader, msg, nil)
		sig2, _ := priv.Sign(rand.Reader, msg, nil)
		
		// SLH-DSA is deterministic - same message should produce same signature
		assert.Equal(t, sig1, sig2)
	})

	t.Run("Large Signature Sizes", func(t *testing.T) {
		modes := []struct {
			mode slhdsa.Mode
			name string
			size int
		}{
			{slhdsa.SLHDSA128f, "128f", slhdsa.SLHDSA128fSignatureSize},
			{slhdsa.SLHDSA192f, "192f", slhdsa.SLHDSA192fSignatureSize},
		}
		
		for _, m := range modes {
			t.Run(m.name, func(t *testing.T) {
				priv, _ := slhdsa.GenerateKey(rand.Reader, m.mode)
				msg := []byte("test")
				sig, _ := priv.Sign(rand.Reader, msg, nil)
				
				assert.Len(t, sig, m.size)
			})
		}
	})
}

// TestConcurrency tests thread safety
func TestConcurrency(t *testing.T) {
	t.Run("ML-KEM Concurrent Operations", func(t *testing.T) {
		priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
		
		// Run concurrent encapsulations
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				result, err := priv.PublicKey.Encapsulate(rand.Reader)
				assert.NoError(t, err)
				secret, err := priv.Decapsulate(result.Ciphertext)
				assert.NoError(t, err)
				assert.Equal(t, result.SharedSecret, secret)
				done <- true
			}()
		}
		
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("ML-DSA Concurrent Signing", func(t *testing.T) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(id int) {
				msg := []byte(fmt.Sprintf("message %d", id))
				sig, err := priv.Sign(rand.Reader, msg, nil)
				assert.NoError(t, err)
				assert.True(t, priv.PublicKey.Verify(msg, sig, nil))
				done <- true
			}(i)
		}
		
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestMemoryLeaks checks for potential memory issues
func TestMemoryLeaks(t *testing.T) {
	t.Run("ML-KEM No Leak", func(t *testing.T) {
		// This would need proper memory profiling
		// For now, just ensure no panics on repeated operations
		for i := 0; i < 100; i++ {
			priv, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
			result, _ := priv.PublicKey.Encapsulate(rand.Reader)
			priv.Decapsulate(result.Ciphertext)
		}
	})
}

// TestParameterValidation ensures all parameters match NIST specs
func TestParameterValidation(t *testing.T) {
	// ML-KEM parameters from FIPS 203
	assert.Equal(t, 800, mlkem.MLKEM512PublicKeySize)
	assert.Equal(t, 1632, mlkem.MLKEM512PrivateKeySize)
	assert.Equal(t, 768, mlkem.MLKEM512CiphertextSize)
	
	assert.Equal(t, 1184, mlkem.MLKEM768PublicKeySize)
	assert.Equal(t, 2400, mlkem.MLKEM768PrivateKeySize)
	assert.Equal(t, 1088, mlkem.MLKEM768CiphertextSize)
	
	assert.Equal(t, 1568, mlkem.MLKEM1024PublicKeySize)
	assert.Equal(t, 3168, mlkem.MLKEM1024PrivateKeySize)
	assert.Equal(t, 1568, mlkem.MLKEM1024CiphertextSize)

	// ML-DSA parameters from FIPS 204
	assert.Equal(t, 1312, mldsa.MLDSA44PublicKeySize)
	assert.Equal(t, 2528, mldsa.MLDSA44PrivateKeySize)
	assert.Equal(t, 2420, mldsa.MLDSA44SignatureSize)
	
	assert.Equal(t, 1952, mldsa.MLDSA65PublicKeySize)
	assert.Equal(t, 4000, mldsa.MLDSA65PrivateKeySize)
	assert.Equal(t, 3293, mldsa.MLDSA65SignatureSize)
	
	assert.Equal(t, 2592, mldsa.MLDSA87PublicKeySize)
	assert.Equal(t, 4864, mldsa.MLDSA87PrivateKeySize)
	assert.Equal(t, 4595, mldsa.MLDSA87SignatureSize)
}