package precompile

import (
	"testing"
)

func TestPrecompiles(t *testing.T) {
	t.Run("SHAKE256", func(t *testing.T) {
		shake := &SHAKE256{}
		// Test gas calculation
		gas := shake.RequiredGas([]byte{0, 0, 0, 32})
		if gas == 0 {
			t.Error("SHAKE256 gas should not be zero")
		}
	})

	t.Run("Registry", func(t *testing.T) {
		if PostQuantumRegistry == nil {
			t.Error("PostQuantumRegistry should be initialized")
		}
	})
}

func BenchmarkSHAKE256(b *testing.B) {
	shake := &SHAKE256{}
	input := []byte{0, 0, 0, 32, 1, 2, 3, 4}

	for i := 0; i < b.N; i++ {
		_ = shake.RequiredGas(input)
	}
}
