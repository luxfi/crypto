package encryption

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAgeEncryption(t *testing.T) {
	// Test with password
	t.Run("PasswordEncryption", func(t *testing.T) {
		data := []byte("test data for age encryption")
		password := "secure-password-123"

		encrypted, err := EncryptDataWithPassword(data, password)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if bytes.Equal(data, encrypted) {
			t.Fatal("Encrypted data should not equal original")
		}

		// Check if data is recognized as age-encrypted
		if !IsAgeEncrypted(encrypted) {
			t.Fatal("Data should be recognized as age-encrypted")
		}

		decrypted, err := DecryptPrivateKeyWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(data, decrypted) {
			t.Fatal("Decrypted data doesn't match original")
		}

		// Test wrong password
		wrongPassword := "wrong-password"
		_, err = DecryptPrivateKeyWithPassword(encrypted, wrongPassword)
		if err == nil {
			t.Fatal("Should fail with wrong password")
		}
	})

	// Test file encryption
	t.Run("FileEncryption", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputFile := filepath.Join(tmpDir, "input.txt")
		encryptedFile := filepath.Join(tmpDir, "encrypted.age")

		testData := []byte("file encryption test data")
		if err := os.WriteFile(inputFile, testData, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		password := "file-password"

		// Encrypt data
		encrypted, err := EncryptDataWithPassword(testData, password)
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		// Write encrypted data to file
		if err := os.WriteFile(encryptedFile, encrypted, 0644); err != nil {
			t.Fatalf("Failed to write encrypted file: %v", err)
		}

		// Decrypt file
		decrypted, err := DecryptFile(encryptedFile, password)
		if err != nil {
			t.Fatalf("Failed to decrypt file: %v", err)
		}

		if !bytes.Equal(testData, decrypted) {
			t.Fatal("Decrypted file content doesn't match original")
		}

		// Test with unencrypted file
		unencrypted, err := DecryptFile(inputFile, password)
		if err != nil {
			t.Fatalf("Failed to read unencrypted file: %v", err)
		}

		if !bytes.Equal(testData, unencrypted) {
			t.Fatal("Unencrypted file should be returned as-is")
		}
	})

	// Test IsAgeEncrypted
	t.Run("IsAgeEncrypted", func(t *testing.T) {
		// Test with encrypted data
		data := []byte("test data")
		password := "test-password"
		encrypted, err := EncryptDataWithPassword(data, password)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if !IsAgeEncrypted(encrypted) {
			t.Fatal("Should detect age-encrypted data")
		}

		// Test with non-encrypted data
		plainData := []byte("plain text data")
		if IsAgeEncrypted(plainData) {
			t.Fatal("Should not detect plain data as encrypted")
		}

		// Test with data that starts with "age-" but is not encrypted
		fakeAge := []byte("age-something but not encrypted")
		if IsAgeEncrypted(fakeAge) {
			t.Fatal("Should not detect fake age data as encrypted")
		}
	})

	// Test empty data
	t.Run("EmptyData", func(t *testing.T) {
		password := "test-password"
		
		// Encrypt empty data
		encrypted, err := EncryptDataWithPassword([]byte{}, password)
		if err != nil {
			t.Fatalf("Failed to encrypt empty data: %v", err)
		}

		// Decrypt empty data
		decrypted, err := DecryptPrivateKeyWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Failed to decrypt empty data: %v", err)
		}

		if len(decrypted) != 0 {
			t.Fatal("Decrypted empty data should be empty")
		}
	})

	// Test large data
	t.Run("LargeData", func(t *testing.T) {
		// Create 1MB of data
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		password := "large-data-password"

		encrypted, err := EncryptDataWithPassword(largeData, password)
		if err != nil {
			t.Fatalf("Failed to encrypt large data: %v", err)
		}

		decrypted, err := DecryptPrivateKeyWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Failed to decrypt large data: %v", err)
		}

		if !bytes.Equal(largeData, decrypted) {
			t.Fatal("Decrypted large data doesn't match original")
		}
	})
}

func BenchmarkAgeEncryption(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	password := "benchmark-password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := EncryptDataWithPassword(data, password)
		DecryptPrivateKeyWithPassword(encrypted, password)
	}
}

func BenchmarkAgeEncryptionLarge(b *testing.B) {
	// 1MB data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	password := "benchmark-password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := EncryptDataWithPassword(data, password)
		DecryptPrivateKeyWithPassword(encrypted, password)
	}
}

func BenchmarkIsAgeEncrypted(b *testing.B) {
	encrypted, _ := EncryptDataWithPassword([]byte("test"), "password")
	plain := []byte("plain text data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsAgeEncrypted(encrypted)
		IsAgeEncrypted(plain)
	}
}