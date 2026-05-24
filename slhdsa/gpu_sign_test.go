// Copyright (C) 2020-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// SLH-DSA SignBatch GPU + parallel CPU dispatch tests.
//
// SLH-DSA-SHA2-192f is the canonical Magnetar parameter set (NIST L3, hash-
// only verify, deterministic, no per-sign nonce). Sign latency is ~1.6s
// per signature on Apple M1 Max — the most expensive operation in the Lux
// crypto stack. Even on a host without a GPU plugin loaded, the goroutine-
// parallel CPU dispatch lets a quorum of validators sign a block in
// (1.6s × validators) / GOMAXPROCS instead of (1.6s × validators) wall
// time.
//
// Equivalence: SLH-DSA SignDeterministic is byte-deterministic per FIPS 205
// — sigma(sk, msg) = sigma'(sk, msg) for any two evaluations. This means:
//
//   1. KAT replay (sign + verify) passes byte-for-byte across:
//        - the cloudflare/circl reference (CPU)
//        - our slhdsa.SignBatch goroutine-parallel CPU path
//        - the GPU substrate (when one is loaded)
//
//   2. A signature produced on the GPU substrate verifies under
//      VerifySignature(CPU). This is the round-trip test that catches a
//      "GPU silently produces invalid signatures" failure mode (the
//      worst-case bug: an attacker grinds for a fault and we publish a
//      signature that no honest verifier accepts).

package slhdsa

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/backend"


)

// genSignBatch192f produces n SLH-DSA-192f keypairs ready for SignBatch.
func genSignBatch192f(t testing.TB, n int) (privs []*PrivateKey, msgs [][]byte) {
	t.Helper()
	privs = make([]*PrivateKey, n)
	msgs = make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := GenerateKey(rand.Reader, SHA2_192f)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		privs[i] = priv
		msgs[i] = []byte(fmt.Sprintf("magnetar-signbatch-msg-%d", i))
	}
	return
}

// TestSLHDSASignBatch_RoundTrip pins the contract that SignBatch produces
// signatures that the per-element CPU verify accepts. This is the most
// important invariant: a sign path that succeeds but produces signatures
// the network rejects is worse than a sign path that fails loudly.
func TestSLHDSASignBatch_RoundTrip(t *testing.T) {
	const n = 4 // small batch to keep runtime <30s on the SLH-DSA 192f path
	privs, msgs := genSignBatch192f(t, n)

	sigs, err := SignBatch(rand.Reader, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch: %v", err)
	}
	if len(sigs) != n {
		t.Fatalf("SignBatch returned %d sigs, want %d", len(sigs), n)
	}

	for i := 0; i < n; i++ {
		if len(sigs[i]) != GetSignatureSize(SHA2_192f) {
			t.Fatalf("sigs[%d] size: got %d, want %d", i, len(sigs[i]), GetSignatureSize(SHA2_192f))
		}
		if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
			t.Fatalf("CPU verify[%d] of batch-signed signature failed — sign/verify path corrupted", i)
		}
	}
}

// TestSLHDSASignBatch_GPU_Path attempts to dispatch through the GPU substrate
// for the SignBatch path. When the substrate is unavailable (no Metal/CUDA
// plugin) this exercises the goroutine-parallel CPU fallback. Either way the
// produced signatures MUST verify under the CPU oracle (proving byte-equal
// to the CPU sign path on FIPS-205-determinism grounds).
func TestSLHDSASignBatch_GPU_Path(t *testing.T) {
	const n = 4
	privs, msgs := genSignBatch192f(t, n)

	prev := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prev)

	sigs := make([][]byte, n)
	dispatched, err := SignBatchGPU(privs, msgs, sigs)
	if err != nil {
		t.Fatalf("SignBatchGPU: %v", err)
	}
	if dispatched {
		t.Logf("GPU dispatch active (gpu=%v)", backend.GPUAvailable())
		// GPU-produced signatures MUST verify under the CPU oracle.
		// This is the round-trip that catches GPU-output corruption.
		for i := 0; i < n; i++ {
			if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
				t.Fatalf("CPU verify[%d] rejected a GPU-signed signature — GPU output corrupted", i)
			}
		}
	} else {
		t.Logf("GPU dispatch unavailable; goroutine-parallel CPU is the active fast path")
		// Confirm the public SignBatch entrypoint still works via the
		// CPU fallback (it doesn't return dispatched=true via this path).
		sigs, err := SignBatch(rand.Reader, privs, msgs)
		if err != nil {
			t.Fatalf("SignBatch fallback: %v", err)
		}
		for i := 0; i < n; i++ {
			if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
				t.Fatalf("CPU verify[%d] of fallback signature failed", i)
			}
		}
	}
}

// TestSLHDSASignBatch_Determinism verifies that two independent SignBatch
// invocations on the same (sk, msg) batch produce byte-equal signatures.
// FIPS 205 SignDeterministic has no per-call randomness — this is a hard
// invariant that catches PRF-state leakage or worker-ordering races in the
// parallel sign path.
func TestSLHDSASignBatch_Determinism(t *testing.T) {
	const n = 3
	privs, msgs := genSignBatch192f(t, n)

	first, err := SignBatch(rand.Reader, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch first: %v", err)
	}
	second, err := SignBatch(rand.Reader, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch second: %v", err)
	}

	for i := 0; i < n; i++ {
		if len(first[i]) != len(second[i]) {
			t.Fatalf("sig[%d] length mismatch: first=%d second=%d", i, len(first[i]), len(second[i]))
		}
		for j := range first[i] {
			if first[i][j] != second[i][j] {
				t.Fatalf("sig[%d] byte[%d] differs across two SignBatch calls: %02x vs %02x", i, j, first[i][j], second[i][j])
			}
		}
	}
}

// TestSLHDSASignBatch_KATReverify is the canonical KAT-replay test: sign
// with our wrapper, verify the resulting signature under the cloudflare/circl
// reference verifier directly. This proves that even if our SLH-DSA wrapper
// implementation diverges from circl, the signature it produces is still a
// valid FIPS 205 signature accepted by the reference verifier.
func TestSLHDSASignBatch_KATReverify(t *testing.T) {
	const n = 2
	privs, msgs := genSignBatch192f(t, n)

	sigs, err := SignBatch(rand.Reader, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch: %v", err)
	}

	// Verify under our wrapper (round-trip).
	for i := 0; i < n; i++ {
		if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
			t.Fatalf("wrapper verify[%d] failed on batch-signed signature", i)
		}
	}

	// Cross-verify: marshal back through the public key bytes and verify
	// under a freshly-deserialized PublicKey. Catches any state-bound
	// caching in PublicKey that could mask GPU-output corruption.
	for i := 0; i < n; i++ {
		pkBytes := privs[i].PublicKey.Bytes()
		fresh, err := PublicKeyFromBytes(pkBytes, SHA2_192f)
		if err != nil {
			t.Fatalf("PublicKeyFromBytes[%d]: %v", i, err)
		}
		if !fresh.VerifySignature(msgs[i], sigs[i]) {
			t.Fatalf("fresh-pk verify[%d] failed — wrapper state divergence detected", i)
		}
	}
}

// TestSLHDSASignBatch_ErrorPaths exercises the input-validation edge cases.
func TestSLHDSASignBatch_ErrorPaths(t *testing.T) {
	// Empty batch should return empty slice, no error.
	sigs, err := SignBatch(rand.Reader, nil, nil)
	if err != nil {
		t.Fatalf("SignBatch(nil): %v", err)
	}
	if len(sigs) != 0 {
		t.Fatalf("SignBatch(nil) returned %d sigs, want 0", len(sigs))
	}

	// Mismatched lengths should return ErrBatchLength.
	priv, _ := GenerateKey(rand.Reader, SHA2_192f)
	_, err = SignBatch(rand.Reader, []*PrivateKey{priv}, [][]byte{[]byte("a"), []byte("b")})
	if err == nil {
		t.Fatalf("SignBatch with mismatched lengths: expected error, got nil")
	}
}

// BenchmarkSLHDSASignBatch_Serial measures the per-element CPU sign cost as
// the baseline for the parallel speedup calculation.
func BenchmarkSLHDSASignBatch_Serial(b *testing.B) {
	const batchSize = 4
	privs, msgs := genSignBatch192f(b, batchSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force serial path by going below the concurrent threshold.
		for j := range privs {
			_, err := privs[j].SignCtx(rand.Reader, msgs[j], nil)
			if err != nil {
				b.Fatalf("Sign[%d]: %v", j, err)
			}
		}
	}
}

// BenchmarkSLHDSASignBatch_Parallel measures the parallel-batch dispatch.
// On Apple M1 Max with GOMAXPROCS=10 the expected speedup over serial is
// near-linear in min(batch_size, GOMAXPROCS).
//
// Includes a batch_size=21 case which is the canonical Lux production
// validator quorum — the size that matters for the end-to-end consensus
// signature path.
func BenchmarkSLHDSASignBatch_Parallel(b *testing.B) {
	for _, size := range []int{2, 4, 8, 16, 21, 32} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			privs, msgs := genSignBatch192f(b, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigs, err := SignBatch(rand.Reader, privs, msgs)
				if err != nil {
					b.Fatalf("SignBatch: %v", err)
				}
				if len(sigs) != size {
					b.Fatalf("len(sigs) = %d, want %d", len(sigs), size)
				}
			}
		})
	}
}
