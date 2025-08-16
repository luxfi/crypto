package mldsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMLDSAKeyGeneration(t *testing.T) {
	modes := []struct {
		name      string
		mode      Mode
		pubSize   int
		privSize  int
		sigSize   int
	}{
		{"ML-DSA-44", MLDSA44, MLDSA44PublicKeySize, MLDSA44PrivateKeySize, MLDSA44SignatureSize},
		{"ML-DSA-65", MLDSA65, MLDSA65PublicKeySize, MLDSA65PrivateKeySize, MLDSA65SignatureSize},
		{"ML-DSA-87", MLDSA87, MLDSA87PublicKeySize, MLDSA87PrivateKeySize, MLDSA87SignatureSize},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			// Test key generation
			privKey, err := GenerateKey(rand.Reader, tt.mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
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
			_, err = GenerateKey(nil, tt.mode)
			if err == nil {
				t.Error("GenerateKey should fail with nil reader")
			}
		})
	}
}

func TestMLDSASignVerify(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			privKey, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			message := []byte("Test message for ML-DSA signature")
			
			// Sign message
			signature, err := privKey.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify signature
			valid := privKey.PublicKey.Verify(message, signature, nil)
			if !valid {
				t.Error("Valid signature failed verification")
			}

			// Test invalid signature
			signature[0] ^= 0xFF
			valid = privKey.PublicKey.Verify(message, signature, nil)
			if valid {
				t.Error("Invalid signature passed verification")
			}
			signature[0] ^= 0xFF // restore

			// Test wrong message
			wrongMessage := []byte("Wrong message")
			valid = privKey.PublicKey.Verify(wrongMessage, signature, nil)
			if valid {
				t.Error("Signature verified with wrong message")
			}

			// Test empty message
			emptyMessage := []byte{}
			emptySig, err := privKey.Sign(rand.Reader, emptyMessage, nil)
			if err != nil {
				t.Fatalf("Sign empty message failed: %v", err)
			}
			valid = privKey.PublicKey.Verify(emptyMessage, emptySig, nil)
			if !valid {
				t.Error("Empty message signature failed verification")
			}
		})
	}
}

func TestMLDSAKeySerialization(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			// Generate original key
			origKey, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Serialize and deserialize private key using FromBytes functions
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

			// Test signature with deserialized keys
			message := []byte("Test serialization")
			signature, err := newPrivKey.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatalf("Sign with deserialized key failed: %v", err)
			}

			valid := newPubKey.Verify(message, signature, nil)
			if !valid {
				t.Error("Verification with deserialized key failed")
			}
		})
	}
}

func TestMLDSADeterministicSignature(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			privKey, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			message := []byte("Deterministic signature test")
			
			// Sign same message multiple times
			sig1, err := privKey.Sign(nil, message, nil) // nil rand for deterministic
			if err != nil {
				t.Fatalf("First sign failed: %v", err)
			}

			sig2, err := privKey.Sign(nil, message, nil)
			if err != nil {
				t.Fatalf("Second sign failed: %v", err)
			}

			// For deterministic signatures, they should be equal
			// Note: ML-DSA has randomized signing by default
			// This test checks if deterministic mode works when rand is nil
			if privKey.IsDeterministic() && !bytes.Equal(sig1, sig2) {
				t.Error("Deterministic signatures are not equal")
			}

			// Both signatures should verify
			if !privKey.PublicKey.Verify(message, sig1, nil) {
				t.Error("First signature failed verification")
			}
			if !privKey.PublicKey.Verify(message, sig2, nil) {
				t.Error("Second signature failed verification")
			}
		})
	}
}

func TestMLDSAEdgeCases(t *testing.T) {
	t.Run("InvalidMode", func(t *testing.T) {
		_, err := GenerateKey(rand.Reader, Mode(99))
		if err == nil {
			t.Error("GenerateKey should fail with invalid mode")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		var pubKey *PublicKey
		valid := pubKey.Verify([]byte("test"), []byte("sig"), nil)
		if valid {
			t.Error("Nil public key should not verify")
		}
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		var privKey *PrivateKey
		_, err := privKey.Sign(rand.Reader, []byte("test"), nil)
		if err == nil {
			t.Error("Nil private key should not sign")
		}
	})

	t.Run("EmptySignature", func(t *testing.T) {
		privKey, _ := GenerateKey(rand.Reader, MLDSA44)
		valid := privKey.PublicKey.Verify([]byte("test"), []byte{}, nil)
		if valid {
			t.Error("Empty signature should not verify")
		}
	})

	t.Run("WrongSizeSignature", func(t *testing.T) {
		privKey, _ := GenerateKey(rand.Reader, MLDSA44)
		// Wrong size signature
		wrongSig := make([]byte, 100)
		rand.Read(wrongSig)
		valid := privKey.PublicKey.Verify([]byte("test"), wrongSig, nil)
		if valid {
			t.Error("Wrong size signature should not verify")
		}
	})
}

func TestMLDSALargeMessage(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			privKey, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Test with large message (1MB)
			largeMessage := make([]byte, 1024*1024)
			rand.Read(largeMessage)

			signature, err := privKey.Sign(rand.Reader, largeMessage, nil)
			if err != nil {
				t.Fatalf("Sign large message failed: %v", err)
			}

			valid := privKey.PublicKey.Verify(largeMessage, signature, nil)
			if !valid {
				t.Error("Large message signature failed verification")
			}

			// Modify one byte in the middle
			largeMessage[512*1024] ^= 0xFF
			valid = privKey.PublicKey.Verify(largeMessage, signature, nil)
			if valid {
				t.Error("Modified large message passed verification")
			}
		})
	}
}

func TestMLDSAConcurrency(t *testing.T) {
	privKey, err := GenerateKey(rand.Reader, MLDSA44)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Concurrent test message")
	
	// Test concurrent signing
	t.Run("ConcurrentSign", func(t *testing.T) {
		const numGoroutines = 10
		done := make(chan bool, numGoroutines)
		
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				msg := append(message, byte(id))
				sig, err := privKey.Sign(rand.Reader, msg, nil)
				if err != nil {
					t.Errorf("Goroutine %d: Sign failed: %v", id, err)
				}
				valid := privKey.PublicKey.Verify(msg, sig, nil)
				if !valid {
					t.Errorf("Goroutine %d: Verification failed", id)
				}
				done <- true
			}(i)
		}
		
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	// Test concurrent verification
	t.Run("ConcurrentVerify", func(t *testing.T) {
		signature, _ := privKey.Sign(rand.Reader, message, nil)
		const numGoroutines = 10
		done := make(chan bool, numGoroutines)
		
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				valid := privKey.PublicKey.Verify(message, signature, nil)
				if !valid {
					t.Errorf("Goroutine %d: Verification failed", id)
				}
				done <- true
			}(i)
		}
		
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})
}

func BenchmarkMLDSAKeyGen(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-DSA-44", MLDSA44},
		{"ML-DSA-65", MLDSA65},
		{"ML-DSA-87", MLDSA87},
	}

	for _, m := range modes {
		b.Run(m.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := GenerateKey(rand.Reader, m.mode)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLDSASign(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-DSA-44", MLDSA44},
		{"ML-DSA-65", MLDSA65},
		{"ML-DSA-87", MLDSA87},
	}

	message := []byte("Benchmark message for ML-DSA signature performance")

	for _, m := range modes {
		privKey, _ := GenerateKey(rand.Reader, m.mode)
		
		b.Run(m.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := privKey.Sign(rand.Reader, message, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLDSAVerify(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-DSA-44", MLDSA44},
		{"ML-DSA-65", MLDSA65},
		{"ML-DSA-87", MLDSA87},
	}

	message := []byte("Benchmark message for ML-DSA verification performance")

	for _, m := range modes {
		privKey, _ := GenerateKey(rand.Reader, m.mode)
		signature, _ := privKey.Sign(rand.Reader, message, nil)
		
		b.Run(m.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				valid := privKey.PublicKey.Verify(message, signature, nil)
				if !valid {
					b.Fatal("Verification failed")
				}
			}
		})
	}
}

// Helper functions are now in mldsa.go