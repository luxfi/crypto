package mlkem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMLKEMKeyGeneration(t *testing.T) {
	modes := []struct {
		name       string
		mode       Mode
		pubSize    int
		privSize   int
		ctSize     int
		ssSize     int
	}{
		{"ML-KEM-512", MLKEM512, MLKEM512PublicKeySize, MLKEM512PrivateKeySize, MLKEM512CiphertextSize, MLKEM512SharedSecretSize},
		{"ML-KEM-768", MLKEM768, MLKEM768PublicKeySize, MLKEM768PrivateKeySize, MLKEM768CiphertextSize, MLKEM768SharedSecretSize},
		{"ML-KEM-1024", MLKEM1024, MLKEM1024PublicKeySize, MLKEM1024PrivateKeySize, MLKEM1024CiphertextSize, MLKEM1024SharedSecretSize},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			// Test key generation
			privKey, err := GenerateKeyPair(rand.Reader, tt.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Check key sizes
			privBytes := privKey.Bytes()
			if len(privBytes) != tt.privSize {
				t.Errorf("Private key size mismatch: got %d, want %d", len(privBytes), tt.privSize)
			}

			pubBytes := privKey.PublicKey.Bytes()
			if len(pubBytes) != tt.pubSize {
				t.Errorf("Public key size mismatch: got %d, want %d", len(pubBytes), tt.pubSize)
			}

			// Test nil reader
			_, err = GenerateKeyPair(nil, tt.mode)
			if err == nil {
				t.Error("GenerateKeyPair should fail with nil reader")
			}
		})
	}

	// Test invalid mode
	_, err := GenerateKeyPair(rand.Reader, Mode(99))
	if err == nil {
		t.Error("GenerateKeyPair should fail with invalid mode")
	}
}

func TestMLKEMEncapsulateDecapsulate(t *testing.T) {
	modes := []Mode{MLKEM512, MLKEM768, MLKEM1024}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			// Generate key pair
			privKey, err := GenerateKeyPair(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Encapsulate
			encapResult, err := privKey.PublicKey.Encapsulate(rand.Reader)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			// Check ciphertext and shared secret sizes
			var expectedCtSize, expectedSSSize int
			switch mode {
			case MLKEM512:
				expectedCtSize = MLKEM512CiphertextSize
				expectedSSSize = MLKEM512SharedSecretSize
			case MLKEM768:
				expectedCtSize = MLKEM768CiphertextSize
				expectedSSSize = MLKEM768SharedSecretSize
			case MLKEM1024:
				expectedCtSize = MLKEM1024CiphertextSize
				expectedSSSize = MLKEM1024SharedSecretSize
			}

			if len(encapResult.Ciphertext) != expectedCtSize {
				t.Errorf("Ciphertext size mismatch: got %d, want %d", len(encapResult.Ciphertext), expectedCtSize)
			}
			if len(encapResult.SharedSecret) != expectedSSSize {
				t.Errorf("Shared secret size mismatch: got %d, want %d", len(encapResult.SharedSecret), expectedSSSize)
			}

			// Decapsulate
			sharedSecret, err := privKey.Decapsulate(encapResult.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}

			// Verify shared secrets match
			if !bytes.Equal(encapResult.SharedSecret, sharedSecret) {
				t.Error("Shared secrets don't match")
			}

			// Test with wrong ciphertext size
			wrongCiphertext := make([]byte, 100)
			_, err = privKey.Decapsulate(wrongCiphertext)
			if err == nil {
				t.Error("Decapsulate should fail with wrong ciphertext size")
			}

			// Test with tampered ciphertext
			tamperedCiphertext := make([]byte, len(encapResult.Ciphertext))
			copy(tamperedCiphertext, encapResult.Ciphertext)
			tamperedCiphertext[0] ^= 0xFF
			
			// In our placeholder implementation, this will produce different shared secret
			tamperedSecret, err := privKey.Decapsulate(tamperedCiphertext)
			if err != nil {
				t.Fatalf("Decapsulate failed with tampered ciphertext: %v", err)
			}
			if bytes.Equal(encapResult.SharedSecret, tamperedSecret) {
				t.Error("Tampered ciphertext produced same shared secret")
			}
		})
	}
}

func TestMLKEMKeySerialization(t *testing.T) {
	modes := []Mode{MLKEM512, MLKEM768, MLKEM1024}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			// Generate original key
			origKey, err := GenerateKeyPair(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Serialize and deserialize private key
			privBytes := origKey.Bytes()
			newPrivKey, err := PrivateKeyFromBytes(privBytes, mode)
			if err != nil {
				t.Fatalf("PrivateKeyFromBytes failed: %v", err)
			}

			// Check keys are equal
			if !bytes.Equal(origKey.Bytes(), newPrivKey.Bytes()) {
				t.Error("Private key serialization failed")
			}

			// Serialize and deserialize public key
			pubBytes := origKey.PublicKey.Bytes()
			newPubKey, err := PublicKeyFromBytes(pubBytes, mode)
			if err != nil {
				t.Fatalf("PublicKeyFromBytes failed: %v", err)
			}

			if !bytes.Equal(origKey.PublicKey.Bytes(), newPubKey.Bytes()) {
				t.Error("Public key serialization failed")
			}

			// Test encapsulation with deserialized keys
			encapResult, err := newPubKey.Encapsulate(rand.Reader)
			if err != nil {
				t.Fatalf("Encapsulate with deserialized key failed: %v", err)
			}

			sharedSecret, err := newPrivKey.Decapsulate(encapResult.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate with deserialized key failed: %v", err)
			}

			if !bytes.Equal(encapResult.SharedSecret, sharedSecret) {
				t.Error("Shared secrets don't match with deserialized keys")
			}
		})
	}
}

func TestMLKEMMultipleEncapsulations(t *testing.T) {
	modes := []Mode{MLKEM512, MLKEM768, MLKEM1024}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			privKey, err := GenerateKeyPair(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Multiple encapsulations should produce different ciphertexts
			// but all should decapsulate correctly
			numEncaps := 10
			ciphertexts := make([][]byte, numEncaps)
			sharedSecrets := make([][]byte, numEncaps)

			for i := 0; i < numEncaps; i++ {
				encapResult, err := privKey.PublicKey.Encapsulate(rand.Reader)
				if err != nil {
					t.Fatalf("Encapsulate %d failed: %v", i, err)
				}
				ciphertexts[i] = encapResult.Ciphertext
				sharedSecrets[i] = encapResult.SharedSecret
			}

			// Check that ciphertexts are different
			for i := 0; i < numEncaps-1; i++ {
				for j := i + 1; j < numEncaps; j++ {
					if bytes.Equal(ciphertexts[i], ciphertexts[j]) {
						t.Errorf("Ciphertexts %d and %d are identical", i, j)
					}
				}
			}

			// Check that all decapsulate correctly
			for i := 0; i < numEncaps; i++ {
				ss, err := privKey.Decapsulate(ciphertexts[i])
				if err != nil {
					t.Fatalf("Decapsulate %d failed: %v", i, err)
				}
				if !bytes.Equal(ss, sharedSecrets[i]) {
					t.Errorf("Shared secret %d doesn't match", i)
				}
			}
		})
	}
}

func TestMLKEMEdgeCases(t *testing.T) {
	t.Run("InvalidMode", func(t *testing.T) {
		_, err := GenerateKeyPair(rand.Reader, Mode(99))
		if err == nil {
			t.Error("GenerateKeyPair should fail with invalid mode")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		var pubKey *PublicKey
		_, err := pubKey.Encapsulate(rand.Reader)
		if err == nil {
			t.Error("Encapsulate should fail with nil public key")
		}
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		var privKey *PrivateKey
		_, err := privKey.Decapsulate([]byte("test"))
		if err == nil {
			t.Error("Decapsulate should fail with nil private key")
		}
	})

	t.Run("EmptyCiphertext", func(t *testing.T) {
		privKey, _ := GenerateKeyPair(rand.Reader, MLKEM512)
		_, err := privKey.Decapsulate([]byte{})
		if err == nil {
			t.Error("Decapsulate should fail with empty ciphertext")
		}
	})

	t.Run("WrongSizeCiphertext", func(t *testing.T) {
		privKey, _ := GenerateKeyPair(rand.Reader, MLKEM512)
		wrongCt := make([]byte, 100)
		rand.Read(wrongCt)
		_, err := privKey.Decapsulate(wrongCt)
		if err == nil {
			t.Error("Decapsulate should fail with wrong size ciphertext")
		}
	})

	t.Run("InvalidKeyBytes", func(t *testing.T) {
		// Wrong size public key
		_, err := PublicKeyFromBytes([]byte("short"), MLKEM512)
		if err == nil {
			t.Error("PublicKeyFromBytes should fail with wrong size")
		}

		// Wrong size private key
		_, err = PrivateKeyFromBytes([]byte("short"), MLKEM512)
		if err == nil {
			t.Error("PrivateKeyFromBytes should fail with wrong size")
		}
	})
}

func TestMLKEMConcurrency(t *testing.T) {
	privKey, err := GenerateKeyPair(rand.Reader, MLKEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test concurrent encapsulation
	t.Run("ConcurrentEncapsulate", func(t *testing.T) {
		const numGoroutines = 10
		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				encapResult, err := privKey.PublicKey.Encapsulate(rand.Reader)
				if err != nil {
					t.Errorf("Goroutine %d: Encapsulate failed: %v", id, err)
				}
				
				ss, err := privKey.Decapsulate(encapResult.Ciphertext)
				if err != nil {
					t.Errorf("Goroutine %d: Decapsulate failed: %v", id, err)
				}
				
				if !bytes.Equal(ss, encapResult.SharedSecret) {
					t.Errorf("Goroutine %d: Shared secrets don't match", id)
				}
				done <- true
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	// Test concurrent decapsulation
	t.Run("ConcurrentDecapsulate", func(t *testing.T) {
		encapResult, _ := privKey.PublicKey.Encapsulate(rand.Reader)
		const numGoroutines = 10
		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				ss, err := privKey.Decapsulate(encapResult.Ciphertext)
				if err != nil {
					t.Errorf("Goroutine %d: Decapsulate failed: %v", id, err)
				}
				if !bytes.Equal(ss, encapResult.SharedSecret) {
					t.Errorf("Goroutine %d: Shared secret mismatch", id)
				}
				done <- true
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})
}

// Helper function for Mode.String()
func (m Mode) String() string {
	switch m {
	case MLKEM512:
		return "ML-KEM-512"
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return "Unknown"
	}
}

// Helper functions that were missing
func NewPrivateKey(mode Mode) *PrivateKey {
	return &PrivateKey{
		PublicKey: *NewPublicKey(mode),
		data:      make([]byte, getPrivateKeySize(mode)),
	}
}

func NewPublicKey(mode Mode) *PublicKey {
	return &PublicKey{
		mode: mode,
		data: make([]byte, getPublicKeySize(mode)),
	}
}

func getPrivateKeySize(mode Mode) int {
	switch mode {
	case MLKEM512:
		return MLKEM512PrivateKeySize
	case MLKEM768:
		return MLKEM768PrivateKeySize
	case MLKEM1024:
		return MLKEM1024PrivateKeySize
	default:
		return 0
	}
}

func getPublicKeySize(mode Mode) int {
	switch mode {
	case MLKEM512:
		return MLKEM512PublicKeySize
	case MLKEM768:
		return MLKEM768PublicKeySize
	case MLKEM1024:
		return MLKEM1024PublicKeySize
	default:
		return 0
	}
}

func BenchmarkMLKEMKeyGen(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-KEM-512", MLKEM512},
		{"ML-KEM-768", MLKEM768},
		{"ML-KEM-1024", MLKEM1024},
	}

	for _, m := range modes {
		b.Run(m.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := GenerateKeyPair(rand.Reader, m.mode)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLKEMEncapsulate(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-KEM-512", MLKEM512},
		{"ML-KEM-768", MLKEM768},
		{"ML-KEM-1024", MLKEM1024},
	}

	for _, m := range modes {
		privKey, _ := GenerateKeyPair(rand.Reader, m.mode)
		
		b.Run(m.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := privKey.PublicKey.Encapsulate(rand.Reader)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLKEMDecapsulate(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-KEM-512", MLKEM512},
		{"ML-KEM-768", MLKEM768},
		{"ML-KEM-1024", MLKEM1024},
	}

	for _, m := range modes {
		privKey, _ := GenerateKeyPair(rand.Reader, m.mode)
		encapResult, _ := privKey.PublicKey.Encapsulate(rand.Reader)
		
		b.Run(m.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ss, err := privKey.Decapsulate(encapResult.Ciphertext)
				if err != nil {
					b.Fatal(err)
				}
				if len(ss) != 32 {
					b.Fatal("invalid shared secret size")
				}
			}
		})
	}
}