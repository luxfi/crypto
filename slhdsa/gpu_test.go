// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// genBatch produces n SLH-DSA-192f keypairs + signs distinct messages with
// each. SLH-DSA 192f is the canonical Comet cert-profile parameter set per
// the PQ-naming-lock memory (NIST L3, hash-only verify, deterministic).
func genBatch(t testing.TB, n int) (pubs []*PublicKey, msgs [][]byte, sigs [][]byte) {
	t.Helper()
	pubs = make([]*PublicKey, n)
	msgs = make([][]byte, n)
	sigs = make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := GenerateKey(rand.Reader, SHA2_192f)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("comet-batch-msg-%d", i))
		sig, err := priv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		pubs[i] = priv.PublicKey
		msgs[i] = msg
		sigs[i] = sig
	}
	return
}

// cpuVerifyBatch is the deterministic CPU oracle the GPU path must agree
// with. Defined locally so the test does not accidentally test GPU == GPU.
func cpuVerifyBatch(pubs []*PublicKey, msgs, sigs [][]byte) []bool {
	out := make([]bool, len(pubs))
	for i := range pubs {
		out[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
	}
	return out
}

// TestSLHDSABatchEquivalence_CPU_GPU pins the contract that the
// GPU-dispatched batch verify path produces byte-equal accept/reject
// decisions to the per-element CPU verify path. FIPS 205 verify is
// deterministic (no randomness), so the kernel substrate and the Go
// CPU reference MUST agree on every signature.
//
// When the GPU substrate is not available on the host (no Metal/CUDA
// plugin loaded, or CRYPTO_BACKEND != gpu), VerifyBatchGPU returns
// dispatched=false and the harness falls back to CPU — in that case
// the equivalence assertion is trivially true. We still log which
// branch was exercised so CI on a GPU-enabled box catches the real
// dispatch path.
func TestSLHDSABatchEquivalence_CPU_GPU(t *testing.T) {
	const n = 16
	pubs, msgs, sigs := genBatch(t, n)

	cpu := cpuVerifyBatch(pubs, msgs, sigs)
	for i, v := range cpu {
		if !v {
			t.Fatalf("CPU verify[%d] = false on a freshly signed message — broken signing/verify path", i)
		}
	}

	// Force GPU resolution to attempt the GPU path. backend.Resolve
	// gates on gpuhost.Available() so this only actually goes to GPU
	// when a backend plugin is loaded; otherwise it falls through and
	// VerifyBatchGPU returns (false, nil).
	prevBackend := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prevBackend)

	gpu := make([]bool, n)
	dispatched, err := VerifyBatchGPU(pubs, msgs, sigs, gpu)
	if err != nil {
		t.Fatalf("VerifyBatchGPU: %v", err)
	}

	if dispatched {
		t.Logf("GPU dispatch executed (backend=%s, gpuhost.Available=%v)", backend.Default(), gpuhost.Available())
		for i := range cpu {
			if cpu[i] != gpu[i] {
				t.Fatalf("CPU/GPU mismatch at[%d]: cpu=%v gpu=%v", i, cpu[i], gpu[i])
			}
		}
	} else {
		t.Logf("GPU dispatch unavailable on this host (no backend plugin or stub returned ErrNoBackends); CPU/GPU equivalence is trivially true since both paths == CPU")
	}

	// VerifyBatch is the public entry point — it must agree with the
	// CPU oracle regardless of which branch ran.
	all := VerifyBatch(pubs, msgs, sigs)
	for i := range cpu {
		if cpu[i] != all[i] {
			t.Fatalf("VerifyBatch[%d] disagrees with CPU oracle: cpu=%v all=%v", i, cpu[i], all[i])
		}
	}
}

// TestSLHDSABatchEquivalence_Tampered checks that a tampered signature is
// rejected by both the CPU oracle and the GPU dispatch. This catches the
// case where the GPU path silently accepts everything (a worse failure mode
// than rejecting everything).
func TestSLHDSABatchEquivalence_Tampered(t *testing.T) {
	const n = 8
	pubs, msgs, sigs := genBatch(t, n)

	// Flip a bit in signature 3.
	sigs[3] = append([]byte(nil), sigs[3]...)
	sigs[3][0] ^= 0xAA

	prevBackend := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prevBackend)

	cpu := cpuVerifyBatch(pubs, msgs, sigs)
	if cpu[3] {
		t.Fatalf("CPU oracle accepted a tampered signature")
	}

	gpu := make([]bool, n)
	dispatched, err := VerifyBatchGPU(pubs, msgs, sigs, gpu)
	if err != nil {
		t.Fatalf("VerifyBatchGPU: %v", err)
	}
	if dispatched {
		for i := range cpu {
			if cpu[i] != gpu[i] {
				t.Fatalf("CPU/GPU mismatch at[%d] (tampered batch): cpu=%v gpu=%v", i, cpu[i], gpu[i])
			}
		}
	}

	all := VerifyBatch(pubs, msgs, sigs)
	if all[3] {
		t.Fatalf("VerifyBatch accepted tampered signature at[3]")
	}
	for i := range cpu {
		if cpu[i] != all[i] {
			t.Fatalf("VerifyBatch[%d] disagrees with CPU oracle: cpu=%v all=%v", i, cpu[i], all[i])
		}
	}
}

// TestSLHDSABatchEmpty verifies the zero-batch boundary case — neither path
// should crash on an empty input.
func TestSLHDSABatchEmpty(t *testing.T) {
	out := VerifyBatch(nil, nil, nil)
	if len(out) != 0 {
		t.Fatalf("VerifyBatch(nil) returned %d results, want 0", len(out))
	}
}

// BenchmarkSLHDSAVerifyBatch_CPU measures the per-element CPU verify time
// for SLH-DSA-192f across a batch of 21 validators (Lux production quorum).
// Reported as ns/op = batch time; divide by batchSize for per-element.
func BenchmarkSLHDSAVerifyBatch_CPU(b *testing.B) {
	const batchSize = 21
	pubs, msgs, sigs := genBatch(b, batchSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := cpuVerifyBatch(pubs, msgs, sigs)
		for j, v := range out {
			if !v {
				b.Fatalf("verify[%d] failed", j)
			}
		}
	}
}

// BenchmarkSLHDSAVerifyBatch_GPU measures the dispatch path under
// CRYPTO_BACKEND=gpu. When the GPU plugin is not present this benchmark
// reports the dispatch overhead + CPU fallback timing (because
// VerifyBatchGPU returns dispatched=false and VerifyBatch falls back). On
// a GPU-equipped host with a Metal/CUDA plugin loaded this measures the
// real GPU batch throughput.
func BenchmarkSLHDSAVerifyBatch_GPU(b *testing.B) {
	const batchSize = 21
	pubs, msgs, sigs := genBatch(b, batchSize)

	prevBackend := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prevBackend)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := VerifyBatch(pubs, msgs, sigs)
		for j, v := range out {
			if !v {
				b.Fatalf("verify[%d] failed", j)
			}
		}
	}
}
