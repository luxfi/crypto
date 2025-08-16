package hashing

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestComputeHash256(t *testing.T) {
	// Test with known vectors
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			"empty",
			[]byte(""),
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"abc",
			[]byte("abc"),
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			"fox",
			[]byte("The quick brown fox jumps over the lazy dog"),
			"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test ComputeHash256
			hash := ComputeHash256(tc.input)
			hashStr := hex.EncodeToString(hash)
			if hashStr != tc.expected {
				t.Errorf("ComputeHash256(%q) = %s, want %s", tc.input, hashStr, tc.expected)
			}

			// Test ComputeHash256Array
			hashArray := ComputeHash256Array(tc.input)
			hashArrayStr := hex.EncodeToString(hashArray[:])
			if hashArrayStr != tc.expected {
				t.Errorf("ComputeHash256Array(%q) = %s, want %s", tc.input, hashArrayStr, tc.expected)
			}

			// Verify slice and array produce same result
			if !bytes.Equal(hash, hashArray[:]) {
				t.Error("ComputeHash256 and ComputeHash256Array should produce same result")
			}
		})
	}
}

func TestComputeHash160(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			"empty",
			[]byte(""),
			"9c1185a5c5e9fc54612808977ee8f548b2258d31",
		},
		{
			"abc",
			[]byte("abc"),
			"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
		},
		{
			"message digest",
			[]byte("message digest"),
			"5d0689ef49d2fae572b881b123a85ffa21595f36",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test ComputeHash160
			hash := ComputeHash160(tc.input)
			hashStr := hex.EncodeToString(hash)
			if hashStr != tc.expected {
				t.Errorf("ComputeHash160(%q) = %s, want %s", tc.input, hashStr, tc.expected)
			}

			// Test ComputeHash160Array
			hashArray := ComputeHash160Array(tc.input)
			hashArrayStr := hex.EncodeToString(hashArray[:])
			if hashArrayStr != tc.expected {
				t.Errorf("ComputeHash160Array(%q) = %s, want %s", tc.input, hashArrayStr, tc.expected)
			}

			// Verify slice and array produce same result
			if !bytes.Equal(hash, hashArray[:]) {
				t.Error("ComputeHash160 and ComputeHash160Array should produce same result")
			}
		})
	}
}

func TestChecksum(t *testing.T) {
	input := []byte("test input for checksum")
	
	// Test various checksum lengths
	lengths := []int{1, 4, 8, 16, 32}
	
	for _, length := range lengths {
		checksum := Checksum(input, length)
		if len(checksum) != length {
			t.Errorf("Checksum length should be %d, got %d", length, len(checksum))
		}
		
		// Verify checksum is last 'length' bytes of hash
		fullHash := ComputeHash256Array(input)
		expected := fullHash[len(fullHash)-length:]
		if !bytes.Equal(checksum, expected) {
			t.Errorf("Checksum should be last %d bytes of hash", length)
		}
	}
	
	// Test that same input produces same checksum
	checksum1 := Checksum(input, 4)
	checksum2 := Checksum(input, 4)
	if !bytes.Equal(checksum1, checksum2) {
		t.Error("Same input should produce same checksum")
	}
	
	// Test that different input produces different checksum
	input2 := []byte("different input")
	checksum3 := Checksum(input2, 4)
	if bytes.Equal(checksum1, checksum3) {
		t.Error("Different input should produce different checksum")
	}
}

func TestToHash256(t *testing.T) {
	// Test valid conversion
	validBytes := make([]byte, HashLen)
	for i := range validBytes {
		validBytes[i] = byte(i)
	}
	
	hash, err := ToHash256(validBytes)
	if err != nil {
		t.Errorf("ToHash256 with valid bytes should not error: %v", err)
	}
	
	if !bytes.Equal(hash[:], validBytes) {
		t.Error("ToHash256 should copy bytes correctly")
	}
	
	// Test invalid lengths
	invalidLengths := []int{0, 1, 31, 33, 100}
	for _, length := range invalidLengths {
		invalidBytes := make([]byte, length)
		_, err := ToHash256(invalidBytes)
		if err == nil {
			t.Errorf("ToHash256 should error with %d bytes", length)
		}
		if err != nil && err.Error() != ErrInvalidHashLen.Error() && !bytes.Contains([]byte(err.Error()), []byte("invalid hash length")) {
			t.Errorf("Expected ErrInvalidHashLen, got: %v", err)
		}
	}
}

func TestToHash160(t *testing.T) {
	// Test valid conversion
	validBytes := make([]byte, AddrLen)
	for i := range validBytes {
		validBytes[i] = byte(i)
	}
	
	hash, err := ToHash160(validBytes)
	if err != nil {
		t.Errorf("ToHash160 with valid bytes should not error: %v", err)
	}
	
	if !bytes.Equal(hash[:], validBytes) {
		t.Error("ToHash160 should copy bytes correctly")
	}
	
	// Test invalid lengths
	invalidLengths := []int{0, 1, 19, 21, 100}
	for _, length := range invalidLengths {
		invalidBytes := make([]byte, length)
		_, err := ToHash160(invalidBytes)
		if err == nil {
			t.Errorf("ToHash160 should error with %d bytes", length)
		}
		if err != nil && err.Error() != ErrInvalidHashLen.Error() && !bytes.Contains([]byte(err.Error()), []byte("invalid hash length")) {
			t.Errorf("Expected ErrInvalidHashLen, got: %v", err)
		}
	}
}

func TestPubkeyBytesToAddress(t *testing.T) {
	// Test that address generation is consistent
	pubkey := []byte("test public key")
	
	addr1 := PubkeyBytesToAddress(pubkey)
	addr2 := PubkeyBytesToAddress(pubkey)
	
	if !bytes.Equal(addr1, addr2) {
		t.Error("Same pubkey should produce same address")
	}
	
	// Test that different pubkeys produce different addresses
	pubkey2 := []byte("different public key")
	addr3 := PubkeyBytesToAddress(pubkey2)
	
	if bytes.Equal(addr1, addr3) {
		t.Error("Different pubkeys should produce different addresses")
	}
	
	// Test that address is 20 bytes (ripemd160 size)
	if len(addr1) != AddrLen {
		t.Errorf("Address should be %d bytes, got %d", AddrLen, len(addr1))
	}
	
	// Test empty pubkey
	emptyAddr := PubkeyBytesToAddress([]byte{})
	if len(emptyAddr) != AddrLen {
		t.Errorf("Empty pubkey should still produce %d byte address", AddrLen)
	}
}

func TestHashConstants(t *testing.T) {
	// Verify constants match expected values
	if HashLen != 32 {
		t.Errorf("HashLen should be 32, got %d", HashLen)
	}
	
	if AddrLen != 20 {
		t.Errorf("AddrLen should be 20, got %d", AddrLen)
	}
}

func BenchmarkComputeHash256(b *testing.B) {
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeHash256(input)
	}
}

func BenchmarkComputeHash256Array(b *testing.B) {
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeHash256Array(input)
	}
}

func BenchmarkComputeHash160(b *testing.B) {
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeHash160(input)
	}
}

func BenchmarkPubkeyBytesToAddress(b *testing.B) {
	pubkey := make([]byte, 65) // Typical pubkey size
	for i := range pubkey {
		pubkey[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PubkeyBytesToAddress(pubkey)
	}
}

func BenchmarkChecksum(b *testing.B) {
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Checksum(input, 4)
	}
}