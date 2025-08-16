package hpke

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHPKEBasicFlow(t *testing.T) {
	suites := []Suite{
		DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
		DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305,
		DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
		DHKEM_P384_HKDF_SHA384__HKDF_SHA384__AES_256_GCM,
		DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM,
	}

	for _, suite := range suites {
		t.Run(suite.String(), func(t *testing.T) {
			// Generate recipient key pair
			recipientPriv, recipientPub, err := GenerateKeyPair(suite)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}

			// Test data
			plaintext := []byte("Hello, HPKE!")
			aad := []byte("additional authenticated data")
			info := []byte("application info")

			// Create sender context
			senderCtx, enc, err := SetupBaseS(suite, recipientPub, info)
			if err != nil {
				t.Fatalf("failed to setup sender: %v", err)
			}

			// Encrypt
			ciphertext, err := senderCtx.Seal(plaintext, aad)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			// Create receiver context
			receiverCtx, err := SetupBaseR(suite, enc, recipientPriv, info)
			if err != nil {
				t.Fatalf("failed to setup receiver: %v", err)
			}

			// Decrypt
			decrypted, err := receiverCtx.Open(ciphertext, aad)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			// Verify
			if !bytes.Equal(plaintext, decrypted) {
				t.Error("decrypted text doesn't match original")
			}
		})
	}
}

func TestHPKESingleShot(t *testing.T) {
	suite := DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305

	// Generate key pair
	privateKey, publicKey, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Test data
	plaintext := []byte("Single shot encryption test")
	aad := []byte("metadata")
	info := []byte("context info")

	// Single-shot encrypt
	enc, ciphertext, err := SingleShotEncrypt(suite, publicKey, plaintext, aad, info)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Single-shot decrypt
	decrypted, err := SingleShotDecrypt(suite, enc, privateKey, ciphertext, aad, info)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted text doesn't match original")
	}
}

func TestHPKEPSKMode(t *testing.T) {
	suite := DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM

	// Generate key pair
	privateKey, publicKey, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// PSK setup
	psk := []byte("pre-shared-key-32-bytes-long!!!!")
	pskID := []byte("psk-identifier")
	info := []byte("app info")

	// Test data
	plaintext := []byte("PSK mode test")
	aad := []byte("aad")

	// Setup PSK sender
	senderCtx, enc, err := SetupPSKS(suite, publicKey, psk, pskID, info)
	if err != nil {
		t.Fatalf("failed to setup PSK sender: %v", err)
	}

	// Encrypt
	ciphertext, err := senderCtx.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Setup PSK receiver
	receiverCtx, err := SetupPSKR(suite, enc, privateKey, psk, pskID, info)
	if err != nil {
		t.Fatalf("failed to setup PSK receiver: %v", err)
	}

	// Decrypt
	decrypted, err := receiverCtx.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted text doesn't match original")
	}

	// Test with wrong PSK
	wrongPSK := []byte("wrong-pre-shared-key-32-bytes!!!")
	_, err = SetupPSKR(suite, enc, privateKey, wrongPSK, pskID, info)
	if err == nil {
		t.Error("expected error with wrong PSK")
	}
}

func TestHPKEAuthMode(t *testing.T) {
	suite := DHKEM_P384_HKDF_SHA384__HKDF_SHA384__AES_256_GCM

	// Generate sender key pair
	senderPriv, senderPub, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	// Generate recipient key pair
	recipientPriv, recipientPub, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	// Test data
	plaintext := []byte("Authenticated mode test")
	aad := []byte("authenticated data")
	info := []byte("info")

	// Setup auth sender
	senderCtx, enc, err := SetupAuthS(suite, recipientPub, senderPriv, info)
	if err != nil {
		t.Fatalf("failed to setup auth sender: %v", err)
	}

	// Encrypt
	ciphertext, err := senderCtx.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Setup auth receiver
	receiverCtx, err := SetupAuthR(suite, enc, recipientPriv, senderPub, info)
	if err != nil {
		t.Fatalf("failed to setup auth receiver: %v", err)
	}

	// Decrypt
	decrypted, err := receiverCtx.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted text doesn't match original")
	}

	// Test with wrong sender public key
	wrongSenderPriv, wrongSenderPub, _ := GenerateKeyPair(suite)
	_ = wrongSenderPriv
	
	_, err = SetupAuthR(suite, enc, recipientPriv, wrongSenderPub, info)
	if err == nil {
		t.Error("expected error with wrong sender public key")
	}
}

func TestHPKEExport(t *testing.T) {
	suite := DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM

	// Generate key pair
	privateKey, publicKey, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	info := []byte("export test")

	// Setup sender
	senderCtx, enc, err := SetupBaseS(suite, publicKey, info)
	if err != nil {
		t.Fatalf("failed to setup sender: %v", err)
	}

	// Setup receiver
	receiverCtx, err := SetupBaseR(suite, enc, privateKey, info)
	if err != nil {
		t.Fatalf("failed to setup receiver: %v", err)
	}

	// Export from both contexts
	exportContext := []byte("export context")
	exportLength := 32

	senderExport := senderCtx.Export(exportContext, exportLength)
	receiverExport := receiverCtx.Export(exportContext, exportLength)

	// Exports should match
	if !bytes.Equal(senderExport, receiverExport) {
		t.Error("sender and receiver exports don't match")
	}

	// Exports should be deterministic
	senderExport2 := senderCtx.Export(exportContext, exportLength)
	if !bytes.Equal(senderExport, senderExport2) {
		t.Error("export is not deterministic")
	}

	// Different context should give different export
	differentContext := []byte("different context")
	differentExport := senderCtx.Export(differentContext, exportLength)
	if bytes.Equal(senderExport, differentExport) {
		t.Error("different contexts should give different exports")
	}
}

func TestHPKEKeySerialization(t *testing.T) {
	suite := DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM

	// Generate key pair
	privateKey, publicKey, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Serialize keys
	privBytes := privateKey.Bytes()
	pubBytes := publicKey.Bytes()

	// Deserialize keys
	privateKey2, err := PrivateKeyFromBytes(suite, privBytes)
	if err != nil {
		t.Fatalf("failed to deserialize private key: %v", err)
	}

	publicKey2, err := PublicKeyFromBytes(suite, pubBytes)
	if err != nil {
		t.Fatalf("failed to deserialize public key: %v", err)
	}

	// Test that deserialized keys work
	plaintext := []byte("serialization test")
	info := []byte("info")

	// Encrypt with original public key
	senderCtx, enc, err := SetupBaseS(suite, publicKey, info)
	if err != nil {
		t.Fatalf("failed to setup sender: %v", err)
	}
	ciphertext, _ := senderCtx.Seal(plaintext, nil)

	// Decrypt with deserialized private key
	receiverCtx, err := SetupBaseR(suite, enc, privateKey2, info)
	if err != nil {
		t.Fatalf("failed to setup receiver: %v", err)
	}
	decrypted, _ := receiverCtx.Open(ciphertext, nil)

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("deserialized private key doesn't work")
	}

	// Encrypt with deserialized public key
	senderCtx2, enc2, err := SetupBaseS(suite, publicKey2, info)
	if err != nil {
		t.Fatalf("failed to setup sender2: %v", err)
	}
	ciphertext2, _ := senderCtx2.Seal(plaintext, nil)

	// Decrypt with original private key
	receiverCtx2, err := SetupBaseR(suite, enc2, privateKey, info)
	if err != nil {
		t.Fatalf("failed to setup receiver2: %v", err)
	}
	decrypted2, _ := receiverCtx2.Open(ciphertext2, nil)

	if !bytes.Equal(plaintext, decrypted2) {
		t.Error("deserialized public key doesn't work")
	}
}

func TestHPKEDeriveKeyPair(t *testing.T) {
	suite := DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM

	// Get expected seed size
	kem := suite.KEM()
	scheme := kem.Scheme()
	seedSize := scheme.SeedSize()

	// Generate seed
	seed := make([]byte, seedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("failed to generate seed: %v", err)
	}

	// Derive key pair
	privateKey1, publicKey1, err := DeriveKeyPair(suite, seed)
	if err != nil {
		t.Fatalf("failed to derive key pair: %v", err)
	}

	// Derive again with same seed
	privateKey2, publicKey2, err := DeriveKeyPair(suite, seed)
	if err != nil {
		t.Fatalf("failed to derive key pair again: %v", err)
	}

	// Keys should be identical
	if !bytes.Equal(privateKey1.Bytes(), privateKey2.Bytes()) {
		t.Error("derived private keys don't match")
	}
	if !bytes.Equal(publicKey1.Bytes(), publicKey2.Bytes()) {
		t.Error("derived public keys don't match")
	}

	// Test with wrong seed size
	wrongSeed := make([]byte, seedSize+1)
	_, _, err = DeriveKeyPair(suite, wrongSeed)
	if err == nil {
		t.Error("expected error with wrong seed size")
	}
}

func TestHPKEErrorCases(t *testing.T) {
	suite := DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM

	// Test nil public key
	_, _, err := SetupBaseS(suite, nil, nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}

	// Test nil private key
	_, err = SetupBaseR(suite, []byte("fake enc"), nil, nil)
	if err == nil {
		t.Error("expected error for nil private key")
	}

	// Test suite mismatch
	privX25519, pubX25519, _ := GenerateKeyPair(DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM)
	_, _, err = SetupBaseS(DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM, pubX25519, nil)
	if err == nil {
		t.Error("expected error for suite mismatch")
	}
	
	_, err = SetupBaseR(DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM, []byte("enc"), privX25519, nil)
	if err == nil {
		t.Error("expected error for suite mismatch")
	}

	// Test empty PSK
	priv, pub, _ := GenerateKeyPair(suite)
	_, _, err = SetupPSKS(suite, pub, nil, nil, nil)
	if err == nil {
		t.Error("expected error for empty PSK")
	}
	
	_, err = SetupPSKR(suite, []byte("enc"), priv, nil, nil, nil)
	if err == nil {
		t.Error("expected error for empty PSK")
	}
}

func BenchmarkHPKE(b *testing.B) {
	suites := []Suite{
		DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
		DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
		DHKEM_P384_HKDF_SHA384__HKDF_SHA384__AES_256_GCM,
	}

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	for _, suite := range suites {
		b.Run(suite.String(), func(b *testing.B) {
			privateKey, publicKey, _ := GenerateKeyPair(suite)
			info := []byte("benchmark")

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Setup and encrypt
				senderCtx, enc, _ := SetupBaseS(suite, publicKey, info)
				ciphertext, _ := senderCtx.Seal(plaintext, nil)

				// Setup and decrypt
				receiverCtx, _ := SetupBaseR(suite, enc, privateKey, info)
				receiverCtx.Open(ciphertext, nil)
			}
		})
	}
}

func BenchmarkHPKESingleShot(b *testing.B) {
	suite := DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305
	privateKey, publicKey, _ := GenerateKeyPair(suite)
	
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	info := []byte("benchmark")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc, ciphertext, _ := SingleShotEncrypt(suite, publicKey, plaintext, nil, info)
		SingleShotDecrypt(suite, enc, privateKey, ciphertext, nil, info)
	}
}