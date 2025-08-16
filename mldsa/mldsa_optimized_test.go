package mldsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestOptimizedKeyGeneration(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			// Test optimized key generation
			privKey, err := GenerateKeyOptimized(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKeyOptimized failed: %v", err)
			}

			// Verify key sizes
			var expectedPrivSize, expectedPubSize int
			switch mode {
			case MLDSA44:
				expectedPrivSize = MLDSA44PrivateKeySize
				expectedPubSize = MLDSA44PublicKeySize
			case MLDSA65:
				expectedPrivSize = MLDSA65PrivateKeySize
				expectedPubSize = MLDSA65PublicKeySize
			case MLDSA87:
				expectedPrivSize = MLDSA87PrivateKeySize
				expectedPubSize = MLDSA87PublicKeySize
			}

			if len(privKey.Bytes()) != expectedPrivSize {
				t.Errorf("Private key size mismatch: got %d, want %d", len(privKey.Bytes()), expectedPrivSize)
			}
			if len(privKey.PublicKey.Bytes()) != expectedPubSize {
				t.Errorf("Public key size mismatch: got %d, want %d", len(privKey.PublicKey.Bytes()), expectedPubSize)
			}

			// Test nil reader
			_, err = GenerateKeyOptimized(nil, mode)
			if err == nil {
				t.Error("GenerateKeyOptimized should fail with nil reader")
			}
		})
	}

	// Test invalid mode
	_, err := GenerateKeyOptimized(rand.Reader, Mode(99))
	if err == nil {
		t.Error("GenerateKeyOptimized should fail with invalid mode")
	}
}

func TestOptimizedSign(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			privKey, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			message := []byte("Test message for optimized signing")
			
			// Test optimized signing
			signature, err := privKey.OptimizedSign(rand.Reader, message, nil)
			if err != nil {
				t.Fatalf("OptimizedSign failed: %v", err)
			}

			// Verify signature
			valid := privKey.PublicKey.Verify(message, signature, nil)
			if !valid {
				t.Error("Optimized signature failed verification")
			}

			// Test with different message
			wrongMessage := []byte("Wrong message")
			valid = privKey.PublicKey.Verify(wrongMessage, signature, nil)
			if valid {
				t.Error("Signature verified with wrong message")
			}
		})
	}
}

func TestBatchDSA(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			numKeys := 5
			batch, err := NewBatchDSA(mode, numKeys)
			if err != nil {
				t.Fatalf("NewBatchDSA failed: %v", err)
			}

			// Prepare messages
			messages := make([][]byte, numKeys)
			for i := range messages {
				messages[i] = []byte(string(rune('A' + i)) + " Test message for batch signing")
			}

			// Batch sign
			signatures, err := batch.SignBatch(messages)
			if err != nil {
				t.Fatalf("SignBatch failed: %v", err)
			}

			if len(signatures) != numKeys {
				t.Errorf("Expected %d signatures, got %d", numKeys, len(signatures))
			}

			// Batch verify
			results, err := batch.VerifyBatch(messages, signatures)
			if err != nil {
				t.Fatalf("VerifyBatch failed: %v", err)
			}

			for i, valid := range results {
				if !valid {
					t.Errorf("Signature %d failed verification", i)
				}
			}

			// Test with tampered signature
			signatures[0][0] ^= 0xFF
			results, err = batch.VerifyBatch(messages, signatures)
			if err != nil {
				t.Fatalf("VerifyBatch failed: %v", err)
			}
			if results[0] {
				t.Error("Tampered signature passed verification")
			}
			signatures[0][0] ^= 0xFF // restore

			// Test mismatched counts
			wrongMessages := make([][]byte, numKeys-1)
			_, err = batch.SignBatch(wrongMessages)
			if err == nil {
				t.Error("SignBatch should fail with mismatched message count")
			}

			_, err = batch.VerifyBatch(wrongMessages, signatures)
			if err == nil {
				t.Error("VerifyBatch should fail with mismatched count")
			}
		})
	}
}

func TestPrecomputedMLDSA(t *testing.T) {
	modes := []Mode{MLDSA44, MLDSA65, MLDSA87}
	
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			privKey, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			precomputed := NewPrecomputedMLDSA(privKey)

			message := []byte("Test message for caching")
			
			// First sign (cache miss)
			sig1, err := precomputed.SignCached(message)
			if err != nil {
				t.Fatalf("First SignCached failed: %v", err)
			}

			// Second sign (cache hit)
			sig2, err := precomputed.SignCached(message)
			if err != nil {
				t.Fatalf("Second SignCached failed: %v", err)
			}

			// Cached signatures should be identical
			if !bytes.Equal(sig1, sig2) {
				t.Error("Cached signatures are not identical")
			}

			// Both should verify
			valid := privKey.PublicKey.Verify(message, sig1, nil)
			if !valid {
				t.Error("First cached signature failed verification")
			}

			valid = privKey.PublicKey.Verify(message, sig2, nil)
			if !valid {
				t.Error("Second cached signature failed verification")
			}

			// Different message should produce different signature
			message2 := []byte("Different message")
			sig3, err := precomputed.SignCached(message2)
			if err != nil {
				t.Fatalf("SignCached for different message failed: %v", err)
			}

			if bytes.Equal(sig1, sig3) {
				t.Error("Different messages produced same signature")
			}

			valid = privKey.PublicKey.Verify(message2, sig3, nil)
			if !valid {
				t.Error("Third cached signature failed verification")
			}
		})
	}
}

func TestSignatureBufferPool(t *testing.T) {
	// Test getting and putting buffers
	buf1 := getSignatureBuffer(MLDSA44SignatureSize)
	if len(buf1) != MLDSA44SignatureSize {
		t.Errorf("Expected buffer size %d, got %d", MLDSA44SignatureSize, len(buf1))
	}

	// Return buffer to pool
	putSignatureBuffer(buf1)

	// Get buffer again (should get same or similar buffer from pool)
	buf2 := getSignatureBuffer(MLDSA44SignatureSize)
	if len(buf2) != MLDSA44SignatureSize {
		t.Errorf("Expected buffer size %d, got %d", MLDSA44SignatureSize, len(buf2))
	}
	putSignatureBuffer(buf2)

	// Test with larger size than pool default
	largeBuf := getSignatureBuffer(MLDSA87SignatureSize * 2)
	if len(largeBuf) != MLDSA87SignatureSize*2 {
		t.Errorf("Expected buffer size %d, got %d", MLDSA87SignatureSize*2, len(largeBuf))
	}
	// Small buffers should not be pooled
	smallBuf := make([]byte, 100)
	putSignatureBuffer(smallBuf) // Should not panic
}

func TestHelperFunctions(t *testing.T) {
	t.Run("SetBytes", func(t *testing.T) {
		// Test PrivateKey SetBytes
		privKey := NewPrivateKey(MLDSA44)
		data := make([]byte, MLDSA44PrivateKeySize)
		rand.Read(data)
		privKey.SetBytes(data)
		if !bytes.Equal(privKey.Bytes(), data) {
			t.Error("PrivateKey SetBytes failed")
		}

		// Test PublicKey SetBytes
		pubKey := NewPublicKey(MLDSA44)
		pubData := make([]byte, MLDSA44PublicKeySize)
		rand.Read(pubData)
		pubKey.SetBytes(pubData)
		if !bytes.Equal(pubKey.Bytes(), pubData) {
			t.Error("PublicKey SetBytes failed")
		}
	})

	t.Run("GetKeySizes", func(t *testing.T) {
		// Test private key sizes
		if size := getPrivateKeySize(MLDSA44); size != MLDSA44PrivateKeySize {
			t.Errorf("getPrivateKeySize(MLDSA44) = %d, want %d", size, MLDSA44PrivateKeySize)
		}
		if size := getPrivateKeySize(MLDSA65); size != MLDSA65PrivateKeySize {
			t.Errorf("getPrivateKeySize(MLDSA65) = %d, want %d", size, MLDSA65PrivateKeySize)
		}
		if size := getPrivateKeySize(MLDSA87); size != MLDSA87PrivateKeySize {
			t.Errorf("getPrivateKeySize(MLDSA87) = %d, want %d", size, MLDSA87PrivateKeySize)
		}
		if size := getPrivateKeySize(Mode(99)); size != 0 {
			t.Errorf("getPrivateKeySize(invalid) = %d, want 0", size)
		}

		// Test public key sizes
		if size := getPublicKeySize(MLDSA44); size != MLDSA44PublicKeySize {
			t.Errorf("getPublicKeySize(MLDSA44) = %d, want %d", size, MLDSA44PublicKeySize)
		}
		if size := getPublicKeySize(MLDSA65); size != MLDSA65PublicKeySize {
			t.Errorf("getPublicKeySize(MLDSA65) = %d, want %d", size, MLDSA65PublicKeySize)
		}
		if size := getPublicKeySize(MLDSA87); size != MLDSA87PublicKeySize {
			t.Errorf("getPublicKeySize(MLDSA87) = %d, want %d", size, MLDSA87PublicKeySize)
		}
		if size := getPublicKeySize(Mode(99)); size != 0 {
			t.Errorf("getPublicKeySize(invalid) = %d, want 0", size)
		}
	})
}

func BenchmarkOptimizedKeyGen(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-DSA-44", MLDSA44},
		{"ML-DSA-65", MLDSA65},
		{"ML-DSA-87", MLDSA87},
	}

	for _, m := range modes {
		b.Run(m.name+"-Standard", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := GenerateKey(rand.Reader, m.mode)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(m.name+"-Optimized", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := GenerateKeyOptimized(rand.Reader, m.mode)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkOptimizedSign(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"ML-DSA-44", MLDSA44},
		{"ML-DSA-65", MLDSA65},
		{"ML-DSA-87", MLDSA87},
	}

	message := []byte("Benchmark message for optimized signing")

	for _, m := range modes {
		privKey, _ := GenerateKey(rand.Reader, m.mode)
		
		b.Run(m.name+"-Standard", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := privKey.Sign(rand.Reader, message, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(m.name+"-Optimized", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := privKey.OptimizedSign(rand.Reader, message, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBatchOperations(b *testing.B) {
	numKeys := 10
	batch, _ := NewBatchDSA(MLDSA65, numKeys)
	
	messages := make([][]byte, numKeys)
	for i := range messages {
		messages[i] = make([]byte, 32)
		rand.Read(messages[i])
	}

	b.Run("BatchSign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := batch.SignBatch(messages)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	signatures, _ := batch.SignBatch(messages)

	b.Run("BatchVerify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := batch.VerifyBatch(messages, signatures)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}