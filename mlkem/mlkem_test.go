package mlkem

import (
	"testing"
)

func TestMLKEM(t *testing.T) {
	t.Run("ML-KEM-512", func(t *testing.T) {
		// Mode constants use iota starting at 0
		if MLKEM512 != Mode(0) {
			t.Error("ML-KEM-512 mode mismatch")
		}
	})

	t.Run("ML-KEM-768", func(t *testing.T) {
		if MLKEM768 != Mode(1) {
			t.Error("ML-KEM-768 mode mismatch")
		}
	})

	t.Run("ML-KEM-1024", func(t *testing.T) {
		if MLKEM1024 != Mode(2) {
			t.Error("ML-KEM-1024 mode mismatch")
		}
	})
}
