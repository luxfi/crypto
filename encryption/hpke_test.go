// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package encryption

import (
	"bytes"
	"testing"
)

func TestHPKESealOpen(t *testing.T) {
	kp, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}

	plaintext := []byte("hello from Lux HPKE")
	info := []byte("test-context")

	ciphertext, err := HPKESeal(kp.PublicKeyBytes(), info, plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext must differ from plaintext")
	}

	decrypted, err := HPKEOpen(kp, info, ciphertext)
	if err != nil {
		t.Fatalf("HPKEOpen: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestHPKEWrongKey(t *testing.T) {
	kp1, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}
	kp2, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}

	plaintext := []byte("secret message")
	ciphertext, err := HPKESeal(kp1.PublicKeyBytes(), nil, plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	_, err = HPKEOpen(kp2, nil, ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestHPKEWrongInfo(t *testing.T) {
	kp, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}

	plaintext := []byte("context-bound message")
	ciphertext, err := HPKESeal(kp.PublicKeyBytes(), []byte("info-a"), plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	_, err = HPKEOpen(kp, []byte("info-b"), ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong info")
	}
}

func TestHPKEEmptyPlaintext(t *testing.T) {
	kp, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}

	ciphertext, err := HPKESeal(kp.PublicKeyBytes(), nil, []byte{})
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	decrypted, err := HPKEOpen(kp, nil, ciphertext)
	if err != nil {
		t.Fatalf("HPKEOpen: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestHPKEKeyPairRoundTrip(t *testing.T) {
	kp, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}

	privBytes, err := kp.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}
	defer clear(privBytes)

	kp2, err := HPKEKeyPairFromBytes(privBytes)
	if err != nil {
		t.Fatalf("HPKEKeyPairFromBytes: %v", err)
	}

	if !bytes.Equal(kp.PublicKeyBytes(), kp2.PublicKeyBytes()) {
		t.Fatal("public keys do not match after round-trip")
	}

	// Verify decryption works with reconstructed key
	plaintext := []byte("round-trip test")
	ciphertext, err := HPKESeal(kp.PublicKeyBytes(), nil, plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	decrypted, err := HPKEOpen(kp2, nil, ciphertext)
	if err != nil {
		t.Fatalf("HPKEOpen with reconstructed key: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted mismatch with reconstructed key")
	}
}

func TestHPKEOpenNilKeyPair(t *testing.T) {
	_, err := HPKEOpen(nil, nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error with nil key pair")
	}
}

func TestHPKELargeData(t *testing.T) {
	kp, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}

	// 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := HPKESeal(kp.PublicKeyBytes(), nil, plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	decrypted, err := HPKEOpen(kp, nil, ciphertext)
	if err != nil {
		t.Fatalf("HPKEOpen: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("large data decryption mismatch")
	}
}

func TestHybridHPKESealOpen(t *testing.T) {
	kp, err := GenerateHybridHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridHPKEKeyPair: %v", err)
	}

	plaintext := []byte("post-quantum hybrid encryption")
	info := []byte("hybrid-test")

	ciphertext, err := HybridHPKESeal(kp.PublicKeyBytes(), info, plaintext)
	if err != nil {
		t.Fatalf("HybridHPKESeal: %v", err)
	}

	decrypted, err := HybridHPKEOpen(kp, info, ciphertext)
	if err != nil {
		t.Fatalf("HybridHPKEOpen: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("hybrid decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestHybridHPKEWrongKey(t *testing.T) {
	kp1, err := GenerateHybridHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridHPKEKeyPair: %v", err)
	}
	kp2, err := GenerateHybridHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridHPKEKeyPair: %v", err)
	}

	ciphertext, err := HybridHPKESeal(kp1.PublicKeyBytes(), nil, []byte("secret"))
	if err != nil {
		t.Fatalf("HybridHPKESeal: %v", err)
	}

	_, err = HybridHPKEOpen(kp2, nil, ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong hybrid key")
	}
}

func TestHybridHPKEKeyPairRoundTrip(t *testing.T) {
	kp, err := GenerateHybridHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridHPKEKeyPair: %v", err)
	}

	privBytes, err := kp.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}
	defer clear(privBytes)

	kp2, err := HybridHPKEKeyPairFromBytes(privBytes)
	if err != nil {
		t.Fatalf("HybridHPKEKeyPairFromBytes: %v", err)
	}

	if !bytes.Equal(kp.PublicKeyBytes(), kp2.PublicKeyBytes()) {
		t.Fatal("hybrid public keys do not match after round-trip")
	}

	plaintext := []byte("hybrid round-trip")
	ciphertext, err := HybridHPKESeal(kp.PublicKeyBytes(), nil, plaintext)
	if err != nil {
		t.Fatalf("HybridHPKESeal: %v", err)
	}

	decrypted, err := HybridHPKEOpen(kp2, nil, ciphertext)
	if err != nil {
		t.Fatalf("HybridHPKEOpen with reconstructed key: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("hybrid decrypted mismatch with reconstructed key")
	}
}

func TestHybridHPKEOpenNilKeyPair(t *testing.T) {
	_, err := HybridHPKEOpen(nil, nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error with nil hybrid key pair")
	}
}

func BenchmarkHPKESealOpen(b *testing.B) {
	kp, err := GenerateHPKEKeyPair()
	if err != nil {
		b.Fatalf("GenerateHPKEKeyPair: %v", err)
	}
	plaintext := []byte("benchmark data for HPKE seal/open")
	pubBytes := kp.PublicKeyBytes()

	b.ResetTimer()
	for b.Loop() {
		ct, _ := HPKESeal(pubBytes, nil, plaintext)
		HPKEOpen(kp, nil, ct)
	}
}

func BenchmarkHybridHPKESealOpen(b *testing.B) {
	kp, err := GenerateHybridHPKEKeyPair()
	if err != nil {
		b.Fatalf("GenerateHybridHPKEKeyPair: %v", err)
	}
	plaintext := []byte("benchmark data for hybrid HPKE seal/open")
	pubBytes := kp.PublicKeyBytes()

	b.ResetTimer()
	for b.Loop() {
		ct, _ := HybridHPKESeal(pubBytes, nil, plaintext)
		HybridHPKEOpen(kp, nil, ct)
	}
}
