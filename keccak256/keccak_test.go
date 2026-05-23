package keccak256

import (
	"encoding/hex"
	"testing"
)

// Vectors from Ethereum / NIST KAT for Keccak-256 (the original, not SHA3-256).
var vectors = []struct {
	in, want string
}{
	{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
	{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
	{"hello", "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"},
	{"The quick brown fox jumps over the lazy dog", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestSumVectors(t *testing.T) {
	for _, v := range vectors {
		got := Sum([]byte(v.in))
		want := mustHex(t, v.want)
		if string(got[:]) != string(want) {
			t.Errorf("Sum(%q) = %x; want %s", v.in, got, v.want)
		}
	}
}

func TestSumBatchMatchesScalar(t *testing.T) {
	inputs := make([][]byte, 16)
	for i, v := range vectors {
		inputs[i] = []byte(v.in)
	}
	for i := len(vectors); i < 16; i++ {
		inputs[i] = []byte("padding")
	}

	got := SumBatch(inputs)
	for i, in := range inputs {
		want := Sum(in)
		if got[i] != want {
			t.Errorf("batch[%d] mismatch: got %x want %x", i, got[i], want)
		}
	}
}

func TestSumBatchLargeMatchesScalar(t *testing.T) {
	// Cross batch threshold to exercise GPU path when present.
	inputs := make([][]byte, BatchThreshold+8)
	for i := range inputs {
		inputs[i] = []byte("input-" + string(rune('a'+(i%26))))
	}
	got := SumBatch(inputs)
	for i, in := range inputs {
		want := Sum(in)
		if got[i] != want {
			t.Errorf("batch[%d] mismatch", i)
		}
	}
}

func TestNewIncrementalEqualsSum(t *testing.T) {
	in := []byte("The quick brown fox jumps over the lazy dog")
	h := New()
	h.Write(in[:10])
	h.Write(in[10:])
	got := h.Sum(nil)

	want := Sum(in)
	if string(got) != string(want[:]) {
		t.Errorf("incremental %x != contiguous %x", got, want)
	}
}

func TestConcat(t *testing.T) {
	got := Concat([]byte("hello"), []byte(" "), []byte("world"))
	want := Sum([]byte("hello world"))
	if got != want {
		t.Errorf("Concat = %x; want %x", got, want)
	}
}

func TestSumHex(t *testing.T) {
	got := SumHex([]byte("abc"))
	if got != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" {
		t.Errorf("SumHex(abc) = %s", got)
	}
}

func BenchmarkSum(b *testing.B) {
	in := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Sum(in)
	}
}

func BenchmarkSumBatch(b *testing.B) {
	inputs := make([][]byte, BatchThreshold)
	for i := range inputs {
		inputs[i] = make([]byte, 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SumBatch(inputs)
	}
}
