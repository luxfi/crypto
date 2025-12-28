// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package encryption

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func TestXWingGenerateIdentity(t *testing.T) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}
	if id == nil {
		t.Fatal("identity is nil")
	}
	r := id.Recipient()
	if r == nil {
		t.Fatal("recipient is nil")
	}
}

func TestXWingRoundTrip(t *testing.T) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	plaintext := []byte("post-quantum encrypted message via X-Wing")

	ciphertext, err := EncryptWithXWing(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithXWing: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext must differ from plaintext")
	}

	decrypted, err := DecryptWithXWing(ciphertext, id)
	if err != nil {
		t.Fatalf("DecryptWithXWing: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestXWingWrongIdentity(t *testing.T) {
	id1, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}
	id2, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	ciphertext, err := EncryptWithXWing([]byte("secret"), id1.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithXWing: %v", err)
	}

	_, err = DecryptWithXWing(ciphertext, id2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong identity")
	}
}

func TestXWingEmptyData(t *testing.T) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	ciphertext, err := EncryptWithXWing([]byte{}, id.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithXWing empty: %v", err)
	}

	decrypted, err := DecryptWithXWing(ciphertext, id)
	if err != nil {
		t.Fatalf("DecryptWithXWing empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestXWingLargeData(t *testing.T) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	// 1MB payload
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := EncryptWithXWing(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithXWing large: %v", err)
	}

	decrypted, err := DecryptWithXWing(ciphertext, id)
	if err != nil {
		t.Fatalf("DecryptWithXWing large: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("large data round-trip mismatch")
	}
}

func TestXWingMultipleRecipients(t *testing.T) {
	id1, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity 1: %v", err)
	}
	id2, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity 2: %v", err)
	}

	plaintext := []byte("multi-recipient message")

	ciphertext, err := EncryptWithXWing(plaintext, id1.Recipient(), id2.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithXWing multi: %v", err)
	}

	// Both identities can decrypt.
	dec1, err := DecryptWithXWing(ciphertext, id1)
	if err != nil {
		t.Fatalf("DecryptWithXWing id1: %v", err)
	}
	if !bytes.Equal(plaintext, dec1) {
		t.Fatal("id1 decryption mismatch")
	}

	dec2, err := DecryptWithXWing(ciphertext, id2)
	if err != nil {
		t.Fatalf("DecryptWithXWing id2: %v", err)
	}
	if !bytes.Equal(plaintext, dec2) {
		t.Fatal("id2 decryption mismatch")
	}
}

func TestXWingIdentityStringRoundTrip(t *testing.T) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	// Serialize and parse back.
	idStr := id.String()
	id2, err := ParseXWingIdentity(idStr)
	if err != nil {
		t.Fatalf("ParseXWingIdentity: %v", err)
	}

	recStr := id.Recipient().String()
	rec2, err := ParseXWingRecipient(recStr)
	if err != nil {
		t.Fatalf("ParseXWingRecipient: %v", err)
	}

	// Encrypt with parsed recipient, decrypt with parsed identity.
	plaintext := []byte("serialization round-trip")
	ciphertext, err := EncryptWithXWing(plaintext, rec2)
	if err != nil {
		t.Fatalf("EncryptWithXWing parsed: %v", err)
	}

	decrypted, err := DecryptWithXWing(ciphertext, id2)
	if err != nil {
		t.Fatalf("DecryptWithXWing parsed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("parsed key round-trip mismatch")
	}
}

func TestXWingCoexistWithPassword(t *testing.T) {
	// Encrypt with password, then separately with X-Wing.
	// Verifies they can coexist in the same workflow.
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	plaintext := []byte("coexistence test")
	password := "test-password-123"

	// Password-encrypt.
	pwEnc, err := EncryptDataWithPassword(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptDataWithPassword: %v", err)
	}
	pwDec, err := DecryptPrivateKeyWithPassword(pwEnc, password)
	if err != nil {
		t.Fatalf("DecryptPrivateKeyWithPassword: %v", err)
	}
	if !bytes.Equal(plaintext, pwDec) {
		t.Fatal("password round-trip failed")
	}

	// X-Wing encrypt.
	xwEnc, err := EncryptWithXWing(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithXWing: %v", err)
	}
	xwDec, err := DecryptWithXWing(xwEnc, id)
	if err != nil {
		t.Fatalf("DecryptWithXWing: %v", err)
	}
	if !bytes.Equal(plaintext, xwDec) {
		t.Fatal("xwing round-trip failed")
	}

	// The ciphertexts are different (different recipients, different randomness).
	if bytes.Equal(pwEnc, xwEnc) {
		t.Fatal("password and xwing ciphertexts should differ")
	}
}

func TestXWingAgeNativeInterop(t *testing.T) {
	// Encrypt with age's native HybridRecipient, decrypt with our XWingIdentity.
	id, err := GenerateXWingIdentity()
	if err != nil {
		t.Fatalf("GenerateXWingIdentity: %v", err)
	}

	plaintext := []byte("native age interop")

	// Encrypt using age.Encrypt directly with our recipient (which implements age.Recipient).
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Decrypt with our helper.
	decrypted, err := DecryptWithXWing(buf.Bytes(), id)
	if err != nil {
		t.Fatalf("DecryptWithXWing native: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("native interop mismatch")
	}
}

func TestXWingNoRecipients(t *testing.T) {
	_, err := EncryptWithXWing([]byte("data"))
	if err == nil {
		t.Fatal("expected error with no recipients")
	}
}

func TestXWingNoIdentities(t *testing.T) {
	_, err := DecryptWithXWing([]byte("data"))
	if err == nil {
		t.Fatal("expected error with no identities")
	}
}

func BenchmarkXWingRoundTrip(b *testing.B) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		b.Fatalf("GenerateXWingIdentity: %v", err)
	}
	r := id.Recipient()
	plaintext := []byte("benchmark payload for X-Wing age encryption")

	b.ResetTimer()
	for b.Loop() {
		ct, _ := EncryptWithXWing(plaintext, r)
		DecryptWithXWing(ct, id)
	}
}

func BenchmarkXWingLargeData(b *testing.B) {
	id, err := GenerateXWingIdentity()
	if err != nil {
		b.Fatalf("GenerateXWingIdentity: %v", err)
	}
	r := id.Recipient()
	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	b.ResetTimer()
	for b.Loop() {
		ct, _ := EncryptWithXWing(plaintext, r)
		DecryptWithXWing(ct, id)
	}
}
