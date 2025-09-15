package slhdsa

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestOptimizedPerformance tests the optimized SLH-DSA implementation
func TestOptimizedPerformance(t *testing.T) {
	modes := []Mode{
		SLHDSA128f,
		SLHDSA128s,
		SLHDSA192f,
		SLHDSA192s,
		SLHDSA256f,
		SLHDSA256s,
	}
	
	// Initialize precomputation tables
	InitPrecomputation()
	
	for _, mode := range modes {
		t.Run(fmt.Sprintf("Mode_%v", mode), func(t *testing.T) {
			opt := NewOptimized(mode)
			
			// Generate test key pair
			priv, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}
			sk := priv
			pk := &priv.PublicKey
			
			message := []byte("Test message for optimization benchmarks")
			
			// Test optimized signing
			sig, err := opt.OptimizedSign(sk, message)
			if err != nil {
				t.Fatalf("Optimized signing failed: %v", err)
			}
			
			// Test optimized verification
			valid := opt.OptimizedVerify(pk, message, sig)
			if !valid {
				t.Error("Optimized verification failed")
			}
			
			// Verify signature size
			expectedSize := opt.getSignatureSize()
			if len(sig) != expectedSize {
				t.Errorf("Signature size mismatch: got %d, want %d", len(sig), expectedSize)
			}
		})
	}
}

// BenchmarkOptimizedSigning benchmarks optimized signing performance
func BenchmarkOptimizedSigning(b *testing.B) {
	benchmarks := []struct {
		mode Mode
		name string
	}{
		{SLHDSA128f, "128f"},
		{SLHDSA128s, "128s"},
		{SLHDSA192f, "192f"},
		{SLHDSA192s, "192s"},
		{SLHDSA256f, "256f"},
		{SLHDSA256s, "256s"},
	}
	
	InitPrecomputation()
	message := make([]byte, 32)
	
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			opt := NewOptimized(bm.mode)
			sk, _ := GenerateKey(rand.Reader, bm.mode)
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				opt.OptimizedSign(sk, message)
			}
		})
	}
}

// BenchmarkOptimizedVerification benchmarks optimized verification
func BenchmarkOptimizedVerification(b *testing.B) {
	benchmarks := []struct {
		mode Mode
		name string
	}{
		{SLHDSA128f, "128f"},
		{SLHDSA128s, "128s"},
		{SLHDSA192f, "192f"},
		{SLHDSA192s, "192s"},
		{SLHDSA256f, "256f"},
		{SLHDSA256s, "256s"},
	}
	
	InitPrecomputation()
	message := make([]byte, 32)
	
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			opt := NewOptimized(bm.mode)
			priv, _ := GenerateKey(rand.Reader, bm.mode)
			sk := priv
			pk := &priv.PublicKey
			sig, _ := opt.OptimizedSign(sk, message)
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				opt.OptimizedVerify(pk, message, sig)
			}
		})
	}
}

// BenchmarkComparison compares standard vs optimized implementations
func BenchmarkComparison(b *testing.B) {
	mode := SLHDSA128f
	message := make([]byte, 32)
	priv, _ := GenerateKey(rand.Reader, mode)
	sk := priv
	pk := &priv.PublicKey
	_ = pk // Keep pk for consistency

	b.Run("Standard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.Sign(rand.Reader, message, nil)
			// Verify is not needed in benchmark
		}
	})
	
	b.Run("Optimized", func(b *testing.B) {
		opt := NewOptimized(mode)
		InitPrecomputation()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sig, _ := opt.OptimizedSign(sk, message)
			opt.OptimizedVerify(pk, message, sig)
		}
	})
}

// TestParallelPerformance tests parallel processing improvements
func TestParallelPerformance(t *testing.T) {
	mode := SLHDSA128f
	opt := NewOptimized(mode)
	InitPrecomputation()

	priv, _ := GenerateKey(rand.Reader, mode)
	sk := priv
	pk := &priv.PublicKey
	message := make([]byte, 32)
	
	// Test different CPU counts
	cpuCounts := []int{1, 2, 4, 8}
	
	for _, cpus := range cpuCounts {
		if cpus > runtime.NumCPU() {
			continue
		}
		
		t.Run(fmt.Sprintf("CPUs_%d", cpus), func(t *testing.T) {
			runtime.GOMAXPROCS(cpus)
			
			start := time.Now()
			iterations := 100
			
			for i := 0; i < iterations; i++ {
				sig, _ := opt.OptimizedSign(sk, message)
				opt.OptimizedVerify(pk, message, sig)
			}
			
			elapsed := time.Since(start)
			opsPerSec := float64(iterations) / elapsed.Seconds()
			
			t.Logf("CPUs: %d, Ops/sec: %.2f", cpus, opsPerSec)
		})
	}
	
	// Reset to default
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// TestMemoryUsage tests memory efficiency of optimizations
func TestMemoryUsage(t *testing.T) {
	modes := []Mode{SLHDSA128f, SLHDSA128s}
	
	for _, mode := range modes {
		t.Run(fmt.Sprintf("Mode_%v", mode), func(t *testing.T) {
			opt := NewOptimized(mode)
			priv, _ := GenerateKey(rand.Reader, mode)
			sk := priv
			pk := &priv.PublicKey
			message := make([]byte, 32)
			
			// Measure memory allocations
			var m1, m2 runtime.MemStats
			runtime.ReadMemStats(&m1)
			
			// Perform multiple operations
			for i := 0; i < 100; i++ {
				sig, _ := opt.OptimizedSign(sk, message)
				opt.OptimizedVerify(pk, message, sig)
			}
			
			runtime.ReadMemStats(&m2)
			
			allocations := m2.Alloc - m1.Alloc
			t.Logf("Memory allocated: %d bytes", allocations)
			
			// Check that we're using the pool effectively
			if allocations > 10*1024*1024 { // 10MB threshold
				t.Logf("Warning: High memory usage detected")
			}
		})
	}
}

// TestSIMDDetection tests SIMD detection and fallback
func TestSIMDDetection(t *testing.T) {
	opt := NewOptimized(SLHDSA128f)
	
	t.Logf("Architecture: %s", runtime.GOARCH)
	t.Logf("SIMD Enabled: %v", opt.simdEnable)
	
	// Test that both paths work
	priv, _ := GenerateKey(rand.Reader, SLHDSA128f)
	sk := priv
	pk := &priv.PublicKey
	message := []byte("Test message")
	
	// Force SIMD path
	opt.simdEnable = true
	sig1, err := opt.OptimizedSign(sk, message)
	if err != nil {
		t.Fatalf("SIMD signing failed: %v", err)
	}
	
	// Force non-SIMD path
	opt.simdEnable = false
	sig2, err := opt.OptimizedSign(sk, message)
	if err != nil {
		t.Fatalf("Non-SIMD signing failed: %v", err)
	}
	
	// Both should verify
	if !opt.OptimizedVerify(pk, message, sig1) {
		t.Error("SIMD signature verification failed")
	}
	if !opt.OptimizedVerify(pk, message, sig2) {
		t.Error("Non-SIMD signature verification failed")
	}
}

// TestOptimizationMetrics provides detailed performance metrics
func TestOptimizationMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping detailed metrics in short mode")
	}
	
	InitPrecomputation()
	
	configs := []BenchmarkConfig{
		{Mode: SLHDSA128f, MessageSize: 32, Iterations: 100, Parallel: true},
		{Mode: SLHDSA128s, MessageSize: 32, Iterations: 100, Parallel: true},
		{Mode: SLHDSA192f, MessageSize: 32, Iterations: 50, Parallel: true},
		{Mode: SLHDSA192s, MessageSize: 32, Iterations: 50, Parallel: true},
		{Mode: SLHDSA256f, MessageSize: 32, Iterations: 25, Parallel: true},
		{Mode: SLHDSA256s, MessageSize: 32, Iterations: 25, Parallel: true},
	}
	
	t.Log("=== SLH-DSA Optimization Metrics ===")
	t.Log("Mode\t\tSign(ms)\tVerify(ms)\tSign Ops/s\tVerify Ops/s")
	t.Log("----\t\t--------\t----------\t----------\t------------")
	
	for _, config := range configs {
		opt := NewOptimized(config.Mode)
		result := opt.RunBenchmark(config)
		
		signMs := float64(result.SignTime) / 1e6
		verifyMs := float64(result.VerifyTime) / 1e6
		
		t.Logf("%v\t\t%.2f\t\t%.2f\t\t%.0f\t\t%.0f",
			config.Mode,
			signMs,
			verifyMs,
			result.SignOpsPerSec,
			result.VerifyOpsPerSec)
	}
}

// Example usage showing the optimization API
func ExampleOptimizedSLHDSA() {
	// Initialize precomputed tables for best performance
	InitPrecomputation()
	
	// Create optimized instance
	opt := NewOptimized(SLHDSA128f)
	
	// Generate keys
	priv, _ := GenerateKey(rand.Reader, SLHDSA128f)
	sk := priv
	pk := &priv.PublicKey
	
	// Sign message with optimizations
	message := []byte("Hello, Post-Quantum World!")
	signature, _ := opt.OptimizedSign(sk, message)
	
	// Verify with optimizations
	valid := opt.OptimizedVerify(pk, message, signature)
	
	fmt.Printf("Signature valid: %v\n", valid)
	fmt.Printf("Signature size: %d bytes\n", len(signature))
	// Output:
	// Signature valid: true
	// Signature size: 17088 bytes
}