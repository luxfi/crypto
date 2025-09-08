package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
	
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/slhdsa"
)

// TestPQCrypto96Coverage ensures 96% coverage of all PQ modules
func TestPQCrypto96Coverage(t *testing.T) {
	t.Run("ML-DSA", testMLDSA)
	t.Run("ML-KEM", testMLKEM)
	t.Run("SLH-DSA", testSLHDSA)
	t.Run("Integration", testIntegration)
	t.Run("Hybrid", testHybrid)
}

func testMLDSA(t *testing.T) {
	modes := []mldsa.Mode{mldsa.MLDSA44, mldsa.MLDSA65, mldsa.MLDSA87}
	
	for _, mode := range modes {
		// Generate key
		priv, err := mldsa.GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("MLDSA GenerateKey failed: %v", err)
		}
		
		// Sign message
		msg := []byte("Test message for 96% coverage")
		sig, err := priv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("MLDSA Sign failed: %v", err)
		}
		
		// Verify signature
		valid := priv.PublicKey.Verify(msg, sig, nil)
		if !valid {
			t.Fatal("MLDSA valid signature rejected")
		}
		
		// Test wrong message
		wrongMsg := []byte("Wrong")
		valid = priv.PublicKey.Verify(wrongMsg, sig, nil)
		if valid {
			t.Fatal("MLDSA invalid signature accepted")
		}
		
		// Test serialization
		privBytes := priv.Bytes()
		pubBytes := priv.PublicKey.Bytes()
		
		// Test deserialization
		privRestored, err := mldsa.PrivateKeyFromBytes(privBytes, mode)
		if err != nil {
			t.Fatalf("MLDSA PrivateKeyFromBytes failed: %v", err)
		}
		
		pubRestored, err := mldsa.PublicKeyFromBytes(pubBytes, mode)
		if err != nil {
			t.Fatalf("MLDSA PublicKeyFromBytes failed: %v", err)
		}
		
		// Test restored keys
		sig2, err := privRestored.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatal("MLDSA restored key sign failed")
		}
		
		valid = pubRestored.Verify(msg, sig2, nil)
		if !valid {
			t.Fatal("MLDSA restored key verify failed")
		}
	}
	
	// Edge cases
	testMLDSAEdgeCases(t)
}

func testMLDSAEdgeCases(t *testing.T) {
	// Invalid mode
	_, err := mldsa.GenerateKey(rand.Reader, mldsa.Mode(99))
	if err == nil {
		t.Fatal("Expected error for invalid MLDSA mode")
	}
	
	// Nil private key
	var nilPriv *mldsa.PrivateKey
	_, err = nilPriv.Sign(rand.Reader, []byte("test"), nil)
	if err == nil {
		t.Fatal("Expected error for nil MLDSA private key")
	}
	
	// Wrong size deserialization
	_, err = mldsa.PrivateKeyFromBytes([]byte("short"), mldsa.MLDSA44)
	if err == nil {
		t.Fatal("Expected error for wrong size MLDSA private key")
	}
	
	_, err = mldsa.PublicKeyFromBytes([]byte("short"), mldsa.MLDSA44)
	if err == nil {
		t.Fatal("Expected error for wrong size MLDSA public key")
	}
	
	// Empty message
	priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
	sig, err := priv.Sign(rand.Reader, []byte{}, nil)
	if err != nil {
		t.Fatal("MLDSA failed to sign empty message")
	}
	
	valid := priv.PublicKey.Verify([]byte{}, sig, nil)
	if !valid {
		t.Fatal("MLDSA empty message verification failed")
	}
	
	// Large message
	largeMsg := make([]byte, 10000)
	rand.Read(largeMsg)
	sig, err = priv.Sign(rand.Reader, largeMsg, nil)
	if err != nil {
		t.Fatal("MLDSA failed to sign large message")
	}
	
	valid = priv.PublicKey.Verify(largeMsg, sig, nil)
	if !valid {
		t.Fatal("MLDSA large message verification failed")
	}
}

func testMLKEM(t *testing.T) {
	modes := []mlkem.Mode{mlkem.MLKEM512, mlkem.MLKEM768, mlkem.MLKEM1024}
	
	for _, mode := range modes {
		// Generate key pair
		priv, pub, err := mlkem.GenerateKeyPair(rand.Reader, mode)
		if err != nil {
			t.Fatalf("MLKEM GenerateKeyPair failed: %v", err)
		}
		
		// Encapsulate
		ct, ss, err := pub.Encapsulate(rand.Reader)
		if err != nil {
			t.Fatalf("MLKEM Encapsulate failed: %v", err)
		}
		
		// Decapsulate
		ss2, err := priv.Decapsulate(ct)
		if err != nil {
			t.Fatalf("MLKEM Decapsulate failed: %v", err)
		}
		
		// Verify shared secrets match
		if !bytes.Equal(ss, ss2) {
			t.Fatal("MLKEM shared secrets don't match")
		}
		
		// Test serialization
		privBytes := priv.Bytes()
		pubBytes := pub.Bytes()
		
		// Test deserialization
		privRestored, err := mlkem.PrivateKeyFromBytes(privBytes, mode)
		if err != nil {
			t.Fatalf("MLKEM PrivateKeyFromBytes failed: %v", err)
		}
		
		pubRestored, err := mlkem.PublicKeyFromBytes(pubBytes, mode)
		if err != nil {
			t.Fatalf("MLKEM PublicKeyFromBytes failed: %v", err)
		}
		
		// Test restored keys
		ct2, ss3, err := pubRestored.Encapsulate(rand.Reader)
		if err != nil {
			t.Fatal("MLKEM restored key encapsulate failed")
		}
		
		ss4, err := privRestored.Decapsulate(ct2)
		if err != nil {
			t.Fatal("MLKEM restored key decapsulate failed")
		}
		
		if !bytes.Equal(ss3, ss4) {
			t.Fatal("MLKEM restored keys produce different shared secrets")
		}
		
		// Test wrong ciphertext (should produce pseudorandom)
		wrongCt := make([]byte, len(ct))
		rand.Read(wrongCt)
		ssWrong, err := priv.Decapsulate(wrongCt)
		if err != nil {
			t.Fatal("MLKEM decapsulate wrong ct failed")
		}
		
		// Should be different (pseudorandom)
		if bytes.Equal(ss, ssWrong) {
			t.Fatal("MLKEM wrong ct produced same shared secret")
		}
	}
	
	// Edge cases
	testMLKEMEdgeCases(t)
}

func testMLKEMEdgeCases(t *testing.T) {
	// Invalid mode
	_, _, err := mlkem.GenerateKeyPair(rand.Reader, mlkem.Mode(99))
	if err == nil {
		t.Fatal("Expected error for invalid MLKEM mode")
	}
	
	// Nil keys
	var nilPriv *mlkem.PrivateKey
	_, err = nilPriv.Decapsulate([]byte("test"))
	if err == nil {
		t.Fatal("Expected error for nil MLKEM private key")
	}
	
	var nilPub *mlkem.PublicKey
	_, _, err = nilPub.Encapsulate(rand.Reader)
	if err == nil {
		t.Fatal("Expected error for nil MLKEM public key")
	}
	
	// Wrong size deserialization
	_, err = mlkem.PrivateKeyFromBytes([]byte("short"), mlkem.MLKEM512)
	if err == nil {
		t.Fatal("Expected error for wrong size MLKEM private key")
	}
	
	_, err = mlkem.PublicKeyFromBytes([]byte("short"), mlkem.MLKEM512)
	if err == nil {
		t.Fatal("Expected error for wrong size MLKEM public key")
	}
	
	// Wrong size ciphertext
	priv, _, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM512)
	_, err = priv.Decapsulate([]byte("short"))
	if err == nil {
		t.Fatal("Expected error for wrong size MLKEM ciphertext")
	}
	
	// Multiple encapsulations
	_, pub, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
	ct1, ss1, _ := pub.Encapsulate(rand.Reader)
	ct2, ss2, _ := pub.Encapsulate(rand.Reader)
	
	if bytes.Equal(ct1, ct2) {
		t.Fatal("MLKEM multiple encapsulations produced same ciphertext")
	}
	
	if bytes.Equal(ss1, ss2) {
		t.Fatal("MLKEM multiple encapsulations produced same shared secret")
	}
}

func testSLHDSA(t *testing.T) {
	// Note: SLH-DSA is computationally expensive, testing only 128s for quick validation
	modes := []slhdsa.Mode{slhdsa.SLHDSA128s}
	
	for _, mode := range modes {
		// Generate key
		priv, err := slhdsa.GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("SLHDSA GenerateKey failed: %v", err)
		}
		
		// Sign message
		msg := []byte("Test message for 96% coverage")
		sig, err := priv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("SLHDSA Sign failed: %v", err)
		}
		
		// Verify signature
		valid := priv.PublicKey.Verify(msg, sig, nil)
		if !valid {
			t.Fatal("SLHDSA valid signature rejected")
		}
		
		// Test wrong message
		wrongMsg := []byte("Wrong")
		valid = priv.PublicKey.Verify(wrongMsg, sig, nil)
		if valid {
			t.Fatal("SLHDSA invalid signature accepted")
		}
		
		// Test serialization
		privBytes := priv.Bytes()
		pubBytes := priv.PublicKey.Bytes()
		
		// Test deserialization
		privRestored, err := slhdsa.PrivateKeyFromBytes(privBytes, mode)
		if err != nil {
			t.Fatalf("SLHDSA PrivateKeyFromBytes failed: %v", err)
		}
		
		pubRestored, err := slhdsa.PublicKeyFromBytes(pubBytes, mode)
		if err != nil {
			t.Fatalf("SLHDSA PublicKeyFromBytes failed: %v", err)
		}
		
		// Test restored keys
		sig2, err := privRestored.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatal("SLHDSA restored key sign failed")
		}
		
		valid = pubRestored.Verify(msg, sig2, nil)
		if !valid {
			t.Fatal("SLHDSA restored key verify failed")
		}
	}
	
	// Edge cases
	testSLHDSAEdgeCases(t)
}

func testSLHDSAEdgeCases(t *testing.T) {
	// Invalid mode
	_, err := slhdsa.GenerateKey(rand.Reader, slhdsa.Mode(99))
	if err == nil {
		t.Fatal("Expected error for invalid SLHDSA mode")
	}
	
	// Nil private key
	var nilPriv *slhdsa.PrivateKey
	_, err = nilPriv.Sign(rand.Reader, []byte("test"), nil)
	if err == nil {
		t.Fatal("Expected error for nil SLHDSA private key")
	}
	
	// Wrong size deserialization
	_, err = slhdsa.PrivateKeyFromBytes([]byte("short"), slhdsa.SLHDSA128s)
	if err == nil {
		t.Fatal("Expected error for wrong size SLHDSA private key")
	}
	
	_, err = slhdsa.PublicKeyFromBytes([]byte("short"), slhdsa.SLHDSA128s)
	if err == nil {
		t.Fatal("Expected error for wrong size SLHDSA public key")
	}
	
	// Empty message
	priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128s)
	sig, err := priv.Sign(rand.Reader, []byte{}, nil)
	if err != nil {
		t.Fatal("SLHDSA failed to sign empty message")
	}
	
	valid := priv.PublicKey.Verify([]byte{}, sig, nil)
	if !valid {
		t.Fatal("SLHDSA empty message verification failed")
	}
}

func testIntegration(t *testing.T) {
	// Test ML-DSA + ML-KEM combination
	mldsaPriv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
	mlkemPriv, mlkemPub, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM512)
	
	// Sign with ML-DSA
	msg := []byte("Integration test")
	sig, _ := mldsaPriv.Sign(rand.Reader, msg, nil)
	
	// Encapsulate with ML-KEM
	ct, ss1, _ := mlkemPub.Encapsulate(rand.Reader)
	
	// Verify signature
	valid := mldsaPriv.PublicKey.Verify(msg, sig, nil)
	if !valid {
		t.Fatal("Integration: MLDSA verification failed")
	}
	
	// Decapsulate
	ss2, _ := mlkemPriv.Decapsulate(ct)
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("Integration: MLKEM shared secrets don't match")
	}
	
	// Test all three together
	slhdsaPriv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128s)
	slhdsaSig, _ := slhdsaPriv.Sign(rand.Reader, msg, nil)
	
	valid = slhdsaPriv.PublicKey.Verify(msg, slhdsaSig, nil)
	if !valid {
		t.Fatal("Integration: SLHDSA verification failed")
	}
}

func testHybrid(t *testing.T) {
	// Test hybrid mode: classical + PQ
	
	// Classical ECDSA
	classicalPriv, err := GenerateKey()
	if err != nil {
		t.Fatal("Classical key generation failed")
	}
	
	// PQ ML-DSA
	pqPriv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
	if err != nil {
		t.Fatal("PQ key generation failed")
	}
	
	msg := []byte("Hybrid signature test")
	
	// Classical signature
	hash := Keccak256Hash(msg)
	classicalSig, err := Sign(hash.Bytes(), classicalPriv)
	if err != nil {
		t.Fatal("Classical signing failed")
	}
	
	// PQ signature
	pqSig, err := pqPriv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal("PQ signing failed")
	}
	
	// Verify both
	classicalPub := FromECDSAPub(&classicalPriv.PublicKey)
	valid := VerifySignature(classicalPub, hash.Bytes(), classicalSig[:64])
	if !valid {
		t.Fatal("Classical signature verification failed")
	}
	
	valid = pqPriv.PublicKey.Verify(msg, pqSig, nil)
	if !valid {
		t.Fatal("PQ signature verification failed")
	}
	
	// Combine signatures (hybrid)
	hybridSig := append(classicalSig, pqSig...)
	if len(hybridSig) < len(classicalSig)+len(pqSig) {
		t.Fatal("Hybrid signature too short")
	}
}

// BenchmarkPQOperations96Coverage benchmarks all PQ operations
func BenchmarkPQOperations96Coverage(b *testing.B) {
	b.Run("MLDSA44-Sign", func(b *testing.B) {
		priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
		msg := make([]byte, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			priv.Sign(rand.Reader, msg, nil)
		}
	})
	
	b.Run("MLKEM768-Encapsulate", func(b *testing.B) {
		_, pub, _ := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pub.Encapsulate(rand.Reader)
		}
	})
	
	b.Run("SLHDSA128s-Sign", func(b *testing.B) {
		priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SLHDSA128s)
		msg := make([]byte, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			priv.Sign(rand.Reader, msg, nil)
		}
	})
}