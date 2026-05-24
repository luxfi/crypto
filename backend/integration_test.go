package backend_test

// Determinism contract: when a caller flips CRYPTO_BACKEND between vanilla
// and gpu, the output of every public function in luxfi/crypto MUST be
// byte-identical. This test exercises the contract on the algorithms we have
// batch GPU paths for.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/keccak256"
	"github.com/luxfi/crypto/sha256"
)

func TestKeccak256BatchAcrossBackends(t *testing.T) {
	inputs := make([][]byte, keccak256.BatchThreshold+8)
	for i := range inputs {
		buf := make([]byte, 32)
		rand.Read(buf)
		inputs[i] = buf
	}

	prev := backend.Default()
	t.Cleanup(func() { backend.SetDefault(prev) })

	backend.SetDefault(backend.Vanilla)
	vanilla := keccak256.SumBatch(inputs)

	backend.SetDefault(backend.GPU)
	gpu := keccak256.SumBatch(inputs)

	for i := range vanilla {
		if vanilla[i] != gpu[i] {
			t.Errorf("keccak[%d] vanilla=%x gpu=%x", i, vanilla[i], gpu[i])
		}
	}
}

func TestSHA256BatchAcrossBackends(t *testing.T) {
	inputs := make([][]byte, sha256.BatchThreshold+8)
	for i := range inputs {
		buf := make([]byte, 32)
		rand.Read(buf)
		inputs[i] = buf
	}

	prev := backend.Default()
	t.Cleanup(func() { backend.SetDefault(prev) })

	backend.SetDefault(backend.Vanilla)
	vanilla := sha256.Sum256Batch(inputs)

	backend.SetDefault(backend.GPU)
	gpu := sha256.Sum256Batch(inputs)

	for i := range vanilla {
		if !bytes.Equal(vanilla[i][:], gpu[i][:]) {
			t.Errorf("sha256[%d] vanilla=%x gpu=%x", i, vanilla[i], gpu[i])
		}
	}
}
