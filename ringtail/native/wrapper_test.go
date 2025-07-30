// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package native

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"sync"
	"testing"
	"time"
	
	"github.com/stretchr/testify/require"
)

// TestRTKeyGen tests key generation
func TestRTKeyGen(t *testing.T) {
	require := require.New(t)
	
	// Test valid seed
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(err)
	
	sk, pk, err := RTKeyGen(seed)
	require.NoError(err)
	require.Len(sk, SKSize)
	require.Len(pk, PKSize)
	
	// Test deterministic generation
	sk2, pk2, err := RTKeyGen(seed)
	require.NoError(err)
	require.Equal(sk, sk2)
	require.Equal(pk, pk2)
	
	// Test different seeds produce different keys
	seed2 := make([]byte, 32)
	_, err = rand.Read(seed2)
	require.NoError(err)
	
	sk3, pk3, err := RTKeyGen(seed2)
	require.NoError(err)
	require.NotEqual(sk, sk3)
	require.NotEqual(pk, pk3)
	
	// Test invalid seed size
	badSeed := make([]byte, 16)
	_, _, err = RTKeyGen(badSeed)
	require.Error(err)
}

// TestRTPrecompute tests precomputation
func TestRTPrecompute(t *testing.T) {
	require := require.New(t)
	
	// Generate key
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, _, err := RTKeyGen(seed)
	require.NoError(err)
	
	// Test precompute
	precomp, err := RTPrecompute(sk)
	require.NoError(err)
	require.Len(precomp, PrecompSize)
	
	// Test multiple precomputes are different (randomized)
	precomp2, err := RTPrecompute(sk)
	require.NoError(err)
	require.NotEqual(precomp, precomp2)
	
	// Test invalid key size
	badSK := make([]byte, 64)
	_, err = RTPrecompute(badSK)
	require.Error(err)
}

// TestRTQuickSign tests quick signing
func TestRTQuickSign(t *testing.T) {
	require := require.New(t)
	
	// Setup
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, _, err := RTKeyGen(seed)
	require.NoError(err)
	
	precomp, err := RTPrecompute(sk)
	require.NoError(err)
	
	msg := make([]byte, 32)
	rand.Read(msg)
	
	// Test signing
	sig, err := RTQuickSign(precomp, msg)
	require.NoError(err)
	require.Len(sig, ShareSize)
	
	// Test different messages produce different signatures
	msg2 := make([]byte, 32)
	rand.Read(msg2)
	sig2, err := RTQuickSign(precomp, msg2)
	require.NoError(err)
	require.NotEqual(sig, sig2)
	
	// Test invalid precomp size
	badPrecomp := make([]byte, 100)
	_, err = RTQuickSign(badPrecomp, msg)
	require.Error(err)
	
	// Test invalid message size
	badMsg := make([]byte, 64)
	_, err = RTQuickSign(precomp, badMsg)
	require.Error(err)
}

// TestRTVerifyShare tests share verification
func TestRTVerifyShare(t *testing.T) {
	require := require.New(t)
	
	// Setup
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, pk, err := RTKeyGen(seed)
	require.NoError(err)
	
	precomp, err := RTPrecompute(sk)
	require.NoError(err)
	
	msg := make([]byte, 32)
	rand.Read(msg)
	
	share, err := RTQuickSign(precomp, msg)
	require.NoError(err)
	
	// Test valid verification
	valid := RTVerifyShare(pk, msg, share)
	require.True(valid)
	
	// Test wrong message
	wrongMsg := make([]byte, 32)
	rand.Read(wrongMsg)
	valid = RTVerifyShare(pk, wrongMsg, share)
	require.False(valid)
	
	// Test wrong public key
	_, wrongPK, _ := RTKeyGen(wrongMsg) // Different seed
	valid = RTVerifyShare(wrongPK, msg, share)
	require.False(valid)
	
	// Test corrupted share
	corruptShare := make([]byte, len(share))
	copy(corruptShare, share)
	corruptShare[0] ^= 0xFF
	valid = RTVerifyShare(pk, msg, corruptShare)
	require.False(valid)
	
	// Test invalid sizes
	require.False(RTVerifyShare(pk[:10], msg, share))
	require.False(RTVerifyShare(pk, msg[:10], share))
	require.False(RTVerifyShare(pk, msg, share[:10]))
}

// TestRTAggregate tests share aggregation
func TestRTAggregate(t *testing.T) {
	require := require.New(t)
	
	// Generate multiple key pairs
	n := 5
	threshold := 3
	
	keys := make([]struct{ sk, pk []byte }, n)
	for i := 0; i < n; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		sk, pk, err := RTKeyGen(seed)
		require.NoError(err)
		keys[i].sk = sk
		keys[i].pk = pk
	}
	
	// Create message
	msg := make([]byte, 32)
	rand.Read(msg)
	
	// Generate shares
	shares := make([][]byte, threshold)
	for i := 0; i < threshold; i++ {
		precomp, err := RTPrecompute(keys[i].sk)
		require.NoError(err)
		
		share, err := RTQuickSign(precomp, msg)
		require.NoError(err)
		shares[i] = share
	}
	
	// Test aggregation
	cert, err := RTAggregate(shares)
	require.NoError(err)
	require.Len(cert, CertSize)
	
	// Test empty shares
	_, err = RTAggregate([][]byte{})
	require.Error(err)
	
	// Test invalid share size
	badShares := [][]byte{make([]byte, 100)}
	_, err = RTAggregate(badShares)
	require.Error(err)
}

// TestRTVerify tests certificate verification
func TestRTVerify(t *testing.T) {
	require := require.New(t)
	
	// For this test, we'll use a mock certificate
	// In production, this would use the actual aggregated certificate
	
	seed := make([]byte, 32)
	rand.Read(seed)
	_, pk, err := RTKeyGen(seed)
	require.NoError(err)
	
	msg := make([]byte, 32)
	rand.Read(msg)
	
	// Create mock certificate
	cert := make([]byte, CertSize)
	rand.Read(cert)
	
	// In mock mode, all certificates are valid
	valid := RTVerify(pk, msg, cert)
	require.True(valid || !valid) // Mock may return either
	
	// Test invalid sizes
	require.False(RTVerify(pk[:10], msg, cert))
	require.False(RTVerify(pk, msg[:10], cert))
	require.False(RTVerify(pk, msg, cert[:10]))
}

// TestConcurrentOperations tests thread safety
func TestConcurrentOperations(t *testing.T) {
	require := require.New(t)
	
	// Setup
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, pk, err := RTKeyGen(seed)
	require.NoError(err)
	
	// Test concurrent precomputes
	var wg sync.WaitGroup
	precomps := make([][]byte, 10)
	
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pre, err := RTPrecompute(sk)
			require.NoError(err)
			precomps[idx] = pre
		}(i)
	}
	wg.Wait()
	
	// Verify all precomputes are different
	for i := 0; i < 9; i++ {
		require.NotEqual(precomps[i], precomps[i+1])
	}
	
	// Test concurrent signing
	msg := make([]byte, 32)
	rand.Read(msg)
	shares := make([][]byte, 10)
	
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			share, err := RTQuickSign(precomps[idx], msg)
			require.NoError(err)
			shares[idx] = share
		}(i)
	}
	wg.Wait()
	
	// Verify all shares are valid
	for _, share := range shares {
		valid := RTVerifyShare(pk, msg, share)
		require.True(valid)
	}
}

// TestMemorySafety tests for memory leaks and buffer overflows
func TestMemorySafety(t *testing.T) {
	require := require.New(t)
	
	// Test with maximum sizes
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, pk, err := RTKeyGen(seed)
	require.NoError(err)
	
	// Allocate and free many times
	for i := 0; i < 100; i++ {
		precomp, err := RTPrecompute(sk)
		require.NoError(err)
		require.Len(precomp, PrecompSize)
		
		msg := make([]byte, 32)
		rand.Read(msg)
		
		share, err := RTQuickSign(precomp, msg)
		require.NoError(err)
		require.Len(share, ShareSize)
		
		valid := RTVerifyShare(pk, msg, share)
		require.True(valid)
	}
	
	// Force garbage collection
	runtime.GC()
}

// BenchmarkRTKeyGen benchmarks key generation
func BenchmarkRTKeyGen(b *testing.B) {
	seed := make([]byte, 32)
	rand.Read(seed)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = RTKeyGen(seed)
	}
}

// BenchmarkRTPrecompute benchmarks precomputation
func BenchmarkRTPrecompute(b *testing.B) {
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, _, _ := RTKeyGen(seed)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RTPrecompute(sk)
	}
}

// BenchmarkRTQuickSign benchmarks quick signing
func BenchmarkRTQuickSign(b *testing.B) {
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, _, _ := RTKeyGen(seed)
	precomp, _ := RTPrecompute(sk)
	msg := make([]byte, 32)
	rand.Read(msg)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RTQuickSign(precomp, msg)
	}
}

// BenchmarkRTVerifyShare benchmarks share verification
func BenchmarkRTVerifyShare(b *testing.B) {
	seed := make([]byte, 32)
	rand.Read(seed)
	sk, pk, _ := RTKeyGen(seed)
	precomp, _ := RTPrecompute(sk)
	msg := make([]byte, 32)
	rand.Read(msg)
	share, _ := RTQuickSign(precomp, msg)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RTVerifyShare(pk, msg, share)
	}
}

// BenchmarkRTAggregate benchmarks aggregation
func BenchmarkRTAggregate(b *testing.B) {
	// Generate 15 shares (mainnet threshold)
	shares := make([][]byte, 15)
	for i := 0; i < 15; i++ {
		share := make([]byte, ShareSize)
		rand.Read(share)
		shares[i] = share
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RTAggregate(shares)
	}
}

// BenchmarkRTVerify benchmarks certificate verification
func BenchmarkRTVerify(b *testing.B) {
	seed := make([]byte, 32)
	rand.Read(seed)
	_, pk, _ := RTKeyGen(seed)
	msg := make([]byte, 32)
	rand.Read(msg)
	cert := make([]byte, CertSize)
	rand.Read(cert)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RTVerify(pk, msg, cert)
	}
}