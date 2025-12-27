//go:build cgo

package gpu

import (
	"sync"
	"testing"
)

func TestPool32(t *testing.T) {
	buf := GetBuffer32()
	if len(buf) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(buf))
	}

	// Verify zeroed
	for i, b := range buf {
		if b != 0 {
			t.Errorf("buffer not zeroed at index %d: got %d", i, b)
		}
	}

	// Modify and return
	buf[0] = 0xFF
	PutBuffer32(buf)

	// Get again - should be zeroed
	buf2 := GetBuffer32()
	if buf2[0] != 0 {
		t.Errorf("buffer not zeroed after reuse: got %d", buf2[0])
	}
	PutBuffer32(buf2)
}

func TestPool48(t *testing.T) {
	buf := GetBuffer48()
	if len(buf) != 48 {
		t.Errorf("expected 48 bytes, got %d", len(buf))
	}
	PutBuffer48(buf)
}

func TestPool64(t *testing.T) {
	buf := GetBuffer64()
	if len(buf) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(buf))
	}
	PutBuffer64(buf)
}

func TestPool96(t *testing.T) {
	buf := GetBuffer96()
	if len(buf) != 96 {
		t.Errorf("expected 96 bytes, got %d", len(buf))
	}
	PutBuffer96(buf)
}

func TestPool4032(t *testing.T) {
	buf := GetBuffer4032()
	if len(buf) != 4032 {
		t.Errorf("expected 4032 bytes, got %d", len(buf))
	}
	PutBuffer4032(buf)
}

func TestPoolWrongSize(t *testing.T) {
	// Putting wrong size buffer should be silently ignored
	wrongBuf := make([]byte, 16)
	PutBuffer32(wrongBuf) // Should not panic

	// Pool should still work
	buf := GetBuffer32()
	if len(buf) != 32 {
		t.Errorf("pool corrupted after wrong size put")
	}
	PutBuffer32(buf)
}

func TestPoolConcurrent(t *testing.T) {
	const goroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				buf := GetBuffer32()
				if len(buf) != 32 {
					t.Errorf("wrong size from pool")
					return
				}
				// Simulate work
				for j := range buf {
					buf[j] = byte(j)
				}
				PutBuffer32(buf)
			}
		}()
	}

	wg.Wait()
}

func TestSHA3_256Into(t *testing.T) {
	data := []byte("test data for hashing")

	// Using pool + Into function
	buf := GetBuffer32()
	SHA3_256Into(buf, data)

	// Using regular function
	expected := SHA3_256(data)

	// Should match
	for i := range expected {
		if buf[i] != expected[i] {
			t.Errorf("SHA3_256Into mismatch at %d: got %x, want %x", i, buf[i], expected[i])
		}
	}
	PutBuffer32(buf)
}

func BenchmarkPoolGet32(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer32()
		PutBuffer32(buf)
	}
}

func BenchmarkMakeSlice32(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 32)
		_ = buf
	}
}

func BenchmarkPoolGet96(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer96()
		PutBuffer96(buf)
	}
}

func BenchmarkMakeSlice96(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 96)
		_ = buf
	}
}

func BenchmarkPoolGet4032(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer4032()
		PutBuffer4032(buf)
	}
}

func BenchmarkMakeSlice4032(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 4032)
		_ = buf
	}
}

// Benchmark SHA3_256 with and without pooling
func BenchmarkSHA3_256Allocating(b *testing.B) {
	data := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SHA3_256(data)
	}
}

func BenchmarkSHA3_256Pooled(b *testing.B) {
	data := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer32()
		SHA3_256Into(buf, data)
		PutBuffer32(buf)
	}
}
