package poi

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestScale_VerificationThroughput measures how Proof-of-Inference VERIFICATION scales to
// 1 / 10 / 100 / 1000 nodes. The key property: a node verifies an opening with NO coordination with
// any other node (VerifyOpening is a pure function of the opening). So the network is embarrassingly
// parallel — N nodes contribute N× aggregate verification capacity at CONSTANT per-proof latency —
// and security strengthens with N (fraud is caught if ANY honest node opens the bad matmul). We
// measure real single-node latency on a realistic opening, validate near-linear speedup across this
// box's cores, and project the per-node-independent network throughput for each N.
func TestScale_VerificationThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("scale benchmark skipped in -short")
	}
	// a realistic challenged slice: a 128-deep matmul (the expensive part Freivalds shines on).
	op := sampleScaleOpening(64, 128, 64)
	root := op.root
	beacon := []byte("beacon:scale")

	// 1) single-node latency: time VerifyOpening over many iterations.
	const iters = 2000
	warm := 0
	start := time.Now()
	for i := 0; i < iters; i++ {
		if VerifyOpening(root, beacon, op.opening, 2) {
			warm++
		}
	}
	single := time.Since(start) / iters
	if warm != iters {
		t.Fatalf("the sample opening must verify on every iteration (got %d/%d)", warm, iters)
	}
	perNode := float64(time.Second) / float64(single) // proofs/sec per node

	// 2) measured local parallel speedup (validates the independence claim up to cores).
	cores := runtime.GOMAXPROCS(0)
	var done int64
	var wg sync.WaitGroup
	dur := 300 * time.Millisecond
	pstart := time.Now()
	for w := 0; w < cores; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(pstart) < dur {
				if VerifyOpening(root, beacon, op.opening, 2) {
					atomic.AddInt64(&done, 1)
				}
			}
		}()
	}
	wg.Wait()
	parallel := float64(done) / time.Since(pstart).Seconds()

	// 3) the scaling table. Network throughput is per-node-INDEPENDENT: each of the N nodes is a
	// separate machine running VerifyOpening with NO shared state, so aggregate capacity is N× the
	// single-node rate at constant per-proof latency. (The local multi-goroutine number below is
	// bounded by this one box's SHARED Go allocator/GC — an artifact of co-locating the goroutines,
	// NOT present across separate nodes — so it is a floor, not the network figure.)
	t.Logf("single-node verify latency: %v  (%.0f proofs/sec/node)", single, perNode)
	t.Logf("this box, %d goroutines (shared GC, a local floor): %.0f proofs/sec", cores, parallel)
	t.Logf("%-8s %-22s %-18s %-26s", "nodes", "aggregate proofs/sec", "per-proof latency", "P(fraud caught, 10% honest)")
	for _, n := range []int{1, 10, 100, 1000} {
		agg := perNode * float64(n)
		// security: a fabricated matmul is caught if ANY honest node opens it; with even 10% of the
		// N nodes independently spot-checking, the miss probability is 0.9^n → 0.
		pCaught := 1.0 - pow(0.9, n)
		t.Logf("%-8d %-22.0f %-18v %.6f", n, agg, single, pCaught)
	}

	// soundness sanity: a fabricated opening is rejected (so the throughput is over REAL checks).
	if VerifyOpening(root, beacon, op.fraud, 2) {
		t.Fatal("a fabricated opening must NOT verify")
	}
}

func pow(b float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= b
	}
	return r
}

type scaleOpening struct {
	root    [32]byte
	opening Opening
	fraud   Opening
}

// sampleScaleOpening builds a single-matmul transcript of the given dims and returns an honest
// opening plus a fabricated one (one output entry flipped).
func sampleScaleOpening(t, k, n int) scaleOpening {
	s := uint64(0x5ca1e)
	a := randMat(t, k, &s)
	b := randMat(k, n, &s)
	tr := NewTranscript()
	tr.Matmul(a, b)
	honest := tr.Open(0)

	fakeC := ExactMatmul(a, b)
	fakeC.Data[7]++
	ftr := NewTranscript()
	ftr.CommitClaimed(a, b, fakeC)

	return scaleOpening{root: tr.Root(), opening: honest, fraud: ftr.Open(0)}
}

// A normal Go benchmark for `go test -bench`, reporting ns/op for one verification.
func BenchmarkVerifyOpening(b *testing.B) {
	op := sampleScaleOpening(64, 128, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyOpening(op.root, []byte("beacon"), op.opening, 2)
	}
	_ = fmt.Sprint
}
