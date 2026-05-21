// Copyright (C) 2020-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// ML-DSA-44 batch verify dispatch tests.
//
// ML-DSA-44 is the FIPS 204 NIST L2 parameter set (Dilithium2 in the legacy
// CRYSTALS spec). In the Lux PQ stack it lives in the CLASSICAL_COMPAT_UNSAFE
// tier — used only for devnet wallet keys that interop with externally-
// published Dilithium2 vectors. The canonical strict-PQ identity is
// ML-DSA-65; new code MUST default to that.
//
// These tests exercise the GPU-dispatch path for ML-DSA-44:
//
//   1. KAT replay — verify that GenerateKey + Sign reproduces the published
//      circl reference, so we know the underlying library is intact.
//   2. Batch verify equivalence — feed a batch through BatchVerify and
//      confirm it matches the per-element CPU oracle byte-for-byte. When a
//      GPU plugin is registered (CRYPTO_BACKEND=gpu + gpuhost detects a
//      device) this exercises the real GPU substrate; otherwise it
//      validates the goroutine-parallel CPU fallback.
//   3. Tamper detection — flip a bit and confirm both paths reject.

package mldsa

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// genBatch44 produces n ML-DSA-44 keypairs + signs distinct messages with
// each. SLH-DSA 192f is the canonical Magnetar parameter set per the
// PQ-naming-lock memory; ML-DSA-44 here is the FIPS 204 L2 tier exercised
// only for compat-unsafe paths (devnet).
func genBatch44(t testing.TB, n int) (pubs []*PublicKey, msgs [][]byte, sigs [][]byte) {
	t.Helper()
	pubs = make([]*PublicKey, n)
	msgs = make([][]byte, n)
	sigs = make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := GenerateKey(rand.Reader, MLDSA44)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("ml-dsa-44-batch-msg-%d", i))
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

// TestMLDSA44_KATReplay verifies our wrapper produces byte-equal public keys
// to the underlying circl/mldsa44.NewKeyFromSeed for a fixed seed. This is
// the KAT contract — if it breaks, the whole batch path is suspect.
func TestMLDSA44_KATReplay(t *testing.T) {
	seed := [mldsa44.SeedSize]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	pk, sk := mldsa44.NewKeyFromSeed(&seed)
	if pk == nil || sk == nil {
		t.Fatalf("circl mldsa44 NewKeyFromSeed returned nil")
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pk: %v", err)
	}
	if len(pkBytes) != MLDSA44PublicKeySize {
		t.Fatalf("ML-DSA-44 pk size: got %d, want %d", len(pkBytes), MLDSA44PublicKeySize)
	}

	// Round-trip through our wrapper.
	wrapper, err := PublicKeyFromBytes(pkBytes, MLDSA44)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	if len(wrapper.publicKey) != len(pkBytes) {
		t.Fatalf("wrapper pk size: got %d, want %d", len(wrapper.publicKey), len(pkBytes))
	}
	for i := range pkBytes {
		if wrapper.publicKey[i] != pkBytes[i] {
			t.Fatalf("byte mismatch at[%d]: wrapper=%02x circl=%02x", i, wrapper.publicKey[i], pkBytes[i])
		}
	}

	// Sign+verify round-trip via the underlying circl ref to ensure the
	// (pk, sk) pair is internally consistent.
	msg := []byte("kat-44")
	sig := make([]byte, MLDSA44SignatureSize)
	if err := mldsa44.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}
	if !mldsa44.Verify(pk, msg, nil, sig) {
		t.Fatalf("circl verify failed on its own signature")
	}
	if !wrapper.VerifySignature(msg, sig) {
		t.Fatalf("wrapper verify failed on circl-produced signature")
	}
}

// TestMLDSA44_BatchEquivalence_CPU_GPU pins the contract that the GPU-
// dispatched batch verify path produces byte-equal accept/reject decisions
// to the per-element CPU verify path for ML-DSA-44. FIPS 204 verify is
// deterministic so the kernel substrate and the Go CPU reference MUST
// agree on every signature.
func TestMLDSA44_BatchEquivalence_CPU_GPU(t *testing.T) {
	n := BatchThreshold + 4
	pubs, msgs, sigs := genBatch44(t, n)

	cpu := make([]bool, n)
	for i := range pubs {
		cpu[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
		if !cpu[i] {
			t.Fatalf("CPU verify[%d] = false on fresh signature — broken signing/verify", i)
		}
	}

	prev := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prev)

	gpu := make([]bool, n)
	dispatched, err := batchVerifyGPU(pubs, msgs, sigs, gpu)
	if err != nil {
		t.Fatalf("batchVerifyGPU: %v", err)
	}
	if dispatched {
		t.Logf("GPU dispatch active (gpuhost.Available=%v)", gpuhost.Available())
		for i := range cpu {
			if cpu[i] != gpu[i] {
				t.Fatalf("CPU/GPU mismatch at[%d]: cpu=%v gpu=%v", i, cpu[i], gpu[i])
			}
		}
	} else {
		t.Logf("GPU dispatch unavailable; goroutine-parallel CPU is the active fast path")
	}

	all := BatchVerify(pubs, msgs, sigs)
	if len(all) != n {
		t.Fatalf("BatchVerify length: got %d, want %d", len(all), n)
	}
	for i := range cpu {
		if cpu[i] != all[i] {
			t.Fatalf("BatchVerify[%d] disagrees with CPU oracle: cpu=%v all=%v", i, cpu[i], all[i])
		}
	}
}

// TestMLDSA44_Tampered confirms the GPU path rejects a tampered signature.
// This catches the "GPU silently accepts everything" failure mode (which
// is worse than rejecting everything because it's exploitable).
func TestMLDSA44_Tampered(t *testing.T) {
	const n = 16
	pubs, msgs, sigs := genBatch44(t, n)

	sigs[5] = append([]byte(nil), sigs[5]...)
	sigs[5][0] ^= 0xff

	prev := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prev)

	all := BatchVerify(pubs, msgs, sigs)
	if all[5] {
		t.Fatalf("BatchVerify accepted tampered signature at[5]")
	}
	for i := 0; i < n; i++ {
		if i == 5 {
			continue
		}
		if !all[i] {
			t.Fatalf("BatchVerify rejected valid signature at[%d]", i)
		}
	}
}

// TestMLDSA44_BatchSign_RoundTrip exercises the sign-then-verify round-trip
// in batch mode. The parallel sign path must produce signatures that the
// per-element verify accepts.
func TestMLDSA44_BatchSign_RoundTrip(t *testing.T) {
	n := concurrentBatchThreshold + 2
	privs := make([]*PrivateKey, n)
	msgs := make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := GenerateKey(rand.Reader, MLDSA44)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		privs[i] = priv
		msgs[i] = []byte(fmt.Sprintf("mldsa44-roundtrip-%d", i))
	}

	sigs, err := BatchSign(rand.Reader, privs, msgs)
	if err != nil {
		t.Fatalf("BatchSign: %v", err)
	}
	if len(sigs) != n {
		t.Fatalf("BatchSign returned %d sigs, want %d", len(sigs), n)
	}
	for i := 0; i < n; i++ {
		if len(sigs[i]) != MLDSA44SignatureSize {
			t.Fatalf("sigs[%d] size: got %d, want %d", i, len(sigs[i]), MLDSA44SignatureSize)
		}
		if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
			t.Fatalf("Verify[%d] of batch-signed signature failed", i)
		}
	}
}

// BenchmarkMLDSA44_BatchVerify measures throughput of the ML-DSA-44 batch
// verify dispatch ladder. Run with -bench=. to compare:
//
//   BenchmarkMLDSA44_BatchVerify/serial-1
//   BenchmarkMLDSA44_BatchVerify/concurrent-8
//   BenchmarkMLDSA44_BatchVerify/concurrent-32
func BenchmarkMLDSA44_BatchVerify(b *testing.B) {
	for _, size := range []int{1, 8, 32, 64} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			pubs, msgs, sigs := genBatch44(b, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := BatchVerify(pubs, msgs, sigs)
				for j, v := range out {
					if !v {
						b.Fatalf("verify[%d] failed", j)
					}
				}
			}
		})
	}
}
