package mldsa

import (
	"testing"
)

func TestMLDSA(t *testing.T) {
	t.Run("ML-DSA-44", func(t *testing.T) {
		// Placeholder test
		if MLDSA44 != Mode(2) {
			t.Error("ML-DSA-44 mode mismatch")
		}
	})

	t.Run("ML-DSA-65", func(t *testing.T) {
		// Placeholder test
		if MLDSA65 != Mode(3) {
			t.Error("ML-DSA-65 mode mismatch")
		}
	})

	t.Run("ML-DSA-87", func(t *testing.T) {
		// Placeholder test
		if MLDSA87 != Mode(5) {
			t.Error("ML-DSA-87 mode mismatch")
		}
	})
}

func BenchmarkMLDSA65(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Placeholder benchmark
		_ = MLDSA65
	}
}
