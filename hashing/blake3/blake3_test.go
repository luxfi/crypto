package blake3

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	h := New()
	if h == nil {
		t.Fatal("New() returned nil")
	}
	if h.h == nil {
		t.Fatal("Internal hasher is nil")
	}
}

func TestNewWithDomain(t *testing.T) {
	domain := "test-domain"
	h1 := NewWithDomain(domain)
	h2 := NewWithDomain(domain)
	
	data := []byte("test data")
	h1.Write(data)
	h2.Write(data)
	
	d1 := h1.Digest()
	d2 := h2.Digest()
	
	if !bytes.Equal(d1[:], d2[:]) {
		t.Error("Same domain should produce same hash")
	}
	
	// Different domain should produce different hash
	h3 := NewWithDomain("different-domain")
	h3.Write(data)
	d3 := h3.Digest()
	
	if bytes.Equal(d1[:], d3[:]) {
		t.Error("Different domain should produce different hash")
	}
}

func TestHashBytes(t *testing.T) {
	// Test with known test vectors
	testCases := []struct {
		input    []byte
		expected string // First 64 bytes of hash
	}{
		{
			[]byte(""),
			"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a",
		},
		{
			[]byte("hello"),
			"ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338c",
		},
	}
	
	for _, tc := range testCases {
		hash := HashBytes(tc.input)
		hashStr := hex.EncodeToString(hash[:])
		if hashStr != tc.expected {
			t.Errorf("HashBytes(%q) = %s, want %s", tc.input, hashStr, tc.expected)
		}
	}
	
	// Test consistency
	data := []byte("test data")
	h1 := HashBytes(data)
	h2 := HashBytes(data)
	
	if !bytes.Equal(h1[:], h2[:]) {
		t.Error("Same input should produce same hash")
	}
}

func TestHashString(t *testing.T) {
	// Test consistency
	s := "test string"
	h1 := HashString(s)
	h2 := HashString(s)
	
	if !bytes.Equal(h1[:], h2[:]) {
		t.Error("Same string should produce same hash")
	}
	
	// Compare with HashBytes
	h3 := HashBytes([]byte(s))
	if !bytes.Equal(h1[:], h3[:]) {
		t.Error("HashString should match HashBytes for same content")
	}
	
	// Different strings produce different hashes
	h4 := HashString("different string")
	if bytes.Equal(h1[:], h4[:]) {
		t.Error("Different strings should produce different hashes")
	}
}

func TestHashWithDomain(t *testing.T) {
	data := []byte("test data")
	domain1 := "domain1"
	domain2 := "domain2"
	
	h1 := HashWithDomain(domain1, data)
	h2 := HashWithDomain(domain1, data)
	h3 := HashWithDomain(domain2, data)
	
	// Same domain and data should produce same hash
	if !bytes.Equal(h1[:], h2[:]) {
		t.Error("Same domain and data should produce same hash")
	}
	
	// Different domain should produce different hash
	if bytes.Equal(h1[:], h3[:]) {
		t.Error("Different domain should produce different hash")
	}
	
	// Should differ from hash without domain
	h4 := HashBytes(data)
	if bytes.Equal(h1[:], h4[:]) {
		t.Error("Hash with domain should differ from hash without domain")
	}
}

func TestWriteMethods(t *testing.T) {
	h := New()
	
	// Test Write
	n, err := h.Write([]byte("test"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != 4 {
		t.Errorf("Write returned %d, want 4", n)
	}
	
	// Test WriteString
	n, err = h.WriteString("string")
	if err != nil {
		t.Errorf("WriteString error: %v", err)
	}
	if n != 6 {
		t.Errorf("WriteString returned %d, want 6", n)
	}
	
	// Test WriteUint32
	h.WriteUint32(0x12345678)
	
	// Test WriteUint64
	h.WriteUint64(0x123456789ABCDEF0)
	
	// Test WriteBigInt
	bigNum := big.NewInt(1234567890)
	h.WriteBigInt(bigNum)
	
	// Test WriteBigInt with nil
	h.WriteBigInt(nil)
	
	// Get digest to ensure it doesn't panic
	_ = h.Digest()
}

func TestWriteUint32(t *testing.T) {
	h1 := New()
	h1.WriteUint32(0x12345678)
	d1 := h1.Digest()
	
	// Should be same as writing the bytes in big-endian
	h2 := New()
	h2.Write([]byte{0x12, 0x34, 0x56, 0x78})
	d2 := h2.Digest()
	
	if !bytes.Equal(d1[:], d2[:]) {
		t.Error("WriteUint32 should write in big-endian format")
	}
}

func TestWriteUint64(t *testing.T) {
	h1 := New()
	h1.WriteUint64(0x123456789ABCDEF0)
	d1 := h1.Digest()
	
	// Should be same as writing the bytes in big-endian
	h2 := New()
	h2.Write([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0})
	d2 := h2.Digest()
	
	if !bytes.Equal(d1[:], d2[:]) {
		t.Error("WriteUint64 should write in big-endian format")
	}
}

func TestWriteBigInt(t *testing.T) {
	// Test with normal big int
	n := big.NewInt(1234567890)
	h1 := New()
	h1.WriteBigInt(n)
	d1 := h1.Digest()
	
	// Writing same number should produce same hash
	h2 := New()
	h2.WriteBigInt(n)
	d2 := h2.Digest()
	
	if !bytes.Equal(d1[:], d2[:]) {
		t.Error("Same big.Int should produce same hash")
	}
	
	// Test with nil
	h3 := New()
	h3.WriteBigInt(nil)
	d3 := h3.Digest()
	
	// Nil should write a zero length prefix
	h4 := New()
	h4.WriteUint32(0)
	d4 := h4.Digest()
	
	if !bytes.Equal(d3[:], d4[:]) {
		t.Error("WriteBigInt(nil) should write zero length")
	}
	
	// Test with zero
	zero := big.NewInt(0)
	h5 := New()
	h5.WriteBigInt(zero)
	_ = h5.Digest() // Should not panic
}

func TestSum(t *testing.T) {
	h := New()
	h.WriteString("test")
	
	// Sum with nil
	sum1 := h.Sum(nil)
	if len(sum1) != 32 { // Default blake3 output
		t.Errorf("Sum(nil) length = %d, want 32", len(sum1))
	}
	
	// Sum with existing slice
	prefix := []byte("prefix")
	sum2 := h.Sum(prefix)
	if !bytes.HasPrefix(sum2, prefix) {
		t.Error("Sum should append to provided slice")
	}
	if len(sum2) != len(prefix)+32 {
		t.Errorf("Sum length = %d, want %d", len(sum2), len(prefix)+32)
	}
}

func TestDigest(t *testing.T) {
	h := New()
	h.WriteString("test")
	d := h.Digest()
	
	if len(d) != DigestLength {
		t.Errorf("Digest length = %d, want %d", len(d), DigestLength)
	}
	
	// Digest should be consistent
	h2 := New()
	h2.WriteString("test")
	d2 := h2.Digest()
	
	if !bytes.Equal(d[:], d2[:]) {
		t.Error("Same input should produce same digest")
	}
}

func TestReader(t *testing.T) {
	h := New()
	h.WriteString("test")
	
	reader := h.Reader()
	if reader == nil {
		t.Fatal("Reader() returned nil")
	}
	
	// Read some bytes
	buf := make([]byte, 100)
	n, err := reader.Read(buf)
	if err != nil {
		t.Errorf("Reader.Read error: %v", err)
	}
	if n != 100 {
		t.Errorf("Reader.Read returned %d, want 100", n)
	}
}

func TestClone(t *testing.T) {
	h1 := New()
	h1.WriteString("test")
	
	h2 := h1.Clone()
	if h2 == nil {
		t.Fatal("Clone() returned nil")
	}
	
	// Both should produce same digest at this point
	d1 := h1.Digest()
	d2 := h2.Digest()
	
	if !bytes.Equal(d1[:], d2[:]) {
		t.Error("Clone should produce same digest")
	}
	
	// Writing to one shouldn't affect the other
	h1.WriteString("more")
	d1New := h1.Digest()
	d2New := h2.Digest()
	
	if bytes.Equal(d1New[:], d2New[:]) {
		t.Error("Writing to original should not affect clone")
	}
}

func TestReset(t *testing.T) {
	h := New()
	h.WriteString("test")
	d1 := h.Digest()
	
	h.Reset()
	h.WriteString("test")
	d2 := h.Digest()
	
	if !bytes.Equal(d1[:], d2[:]) {
		t.Error("Reset should restore initial state")
	}
	
	// After reset, different input should produce different hash
	h.Reset()
	h.WriteString("different")
	d3 := h.Digest()
	
	if bytes.Equal(d1[:], d3[:]) {
		t.Error("After reset, different input should produce different hash")
	}
}

func TestDigestLength(t *testing.T) {
	if DigestLength != 64 {
		t.Errorf("DigestLength = %d, want 64", DigestLength)
	}
}

func BenchmarkHashBytes(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashBytes(data)
	}
}

func BenchmarkHashString(b *testing.B) {
	data := strings.Repeat("benchmark", 128)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashString(data)
	}
}

func BenchmarkWriteBigInt(b *testing.B) {
	n := new(big.Int)
	n.SetString("123456789012345678901234567890123456789012345678901234567890", 10)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.WriteBigInt(n)
		_ = h.Digest()
	}
}