package lamport

import (
	"testing"
)

func TestLamport(t *testing.T) {
	t.Run("SHA256", func(t *testing.T) {
		// Placeholder test
		if SHA256 != HashFunc(0) {
			t.Error("SHA256 hash function mismatch")
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		// Placeholder test
		if SHA512 != HashFunc(1) {
			t.Error("SHA512 hash function mismatch")
		}
	})
}

func BenchmarkLamportSHA256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Placeholder benchmark
		_ = SHA256
	}
}
