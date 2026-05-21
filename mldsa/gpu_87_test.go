// Copyright (C) 2020-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// ML-DSA-87 batch verify dispatch tests.
//
// ML-DSA-87 is the FIPS 204 NIST L5 parameter set (Dilithium5). In the Lux
// PQ stack it's the high-value-tier identity primitive — used for root keys,
// M-Chain custody, and any signing surface where the 256-bit security
// margin is required.
//
// Test plan mirrors the ML-DSA-44 suite but with the larger parameter sizes
// (pk=2592, sk=4896, sig=4627). The verify cost is ~2x ML-DSA-65 and the
// signature is ~40% larger.

package mldsa

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

func genBatch87(t testing.TB, n int) (pubs []*PublicKey, msgs [][]byte, sigs [][]byte) {
	t.Helper()
	pubs = make([]*PublicKey, n)
	msgs = make([][]byte, n)
	sigs = make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := GenerateKey(rand.Reader, MLDSA87)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("ml-dsa-87-batch-msg-%d", i))
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

// TestMLDSA87_KATReplay verifies our wrapper produces byte-equal public keys
// to the underlying circl/mldsa87.NewKeyFromSeed for a fixed seed.
func TestMLDSA87_KATReplay(t *testing.T) {
	seed := [mldsa87.SeedSize]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	pk, sk := mldsa87.NewKeyFromSeed(&seed)
	if pk == nil || sk == nil {
		t.Fatalf("circl mldsa87 NewKeyFromSeed returned nil")
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pk: %v", err)
	}
	if len(pkBytes) != MLDSA87PublicKeySize {
		t.Fatalf("ML-DSA-87 pk size: got %d, want %d", len(pkBytes), MLDSA87PublicKeySize)
	}

	wrapper, err := PublicKeyFromBytes(pkBytes, MLDSA87)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	for i := range pkBytes {
		if wrapper.publicKey[i] != pkBytes[i] {
			t.Fatalf("byte mismatch at[%d]: wrapper=%02x circl=%02x", i, wrapper.publicKey[i], pkBytes[i])
		}
	}

	msg := []byte("kat-87")
	sig := make([]byte, MLDSA87SignatureSize)
	if err := mldsa87.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}
	if !mldsa87.Verify(pk, msg, nil, sig) {
		t.Fatalf("circl verify failed on its own signature")
	}
	if !wrapper.VerifySignature(msg, sig) {
		t.Fatalf("wrapper verify failed on circl-produced signature")
	}
}

// TestMLDSA87_BatchEquivalence_CPU_GPU asserts byte-equal accept/reject
// decisions between the dispatch tiers (GPU substrate if present, parallel
// CPU otherwise) and the per-element CPU oracle.
func TestMLDSA87_BatchEquivalence_CPU_GPU(t *testing.T) {
	n := BatchThreshold + 4
	pubs, msgs, sigs := genBatch87(t, n)

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
	for i := range cpu {
		if cpu[i] != all[i] {
			t.Fatalf("BatchVerify[%d] disagrees with CPU oracle: cpu=%v all=%v", i, cpu[i], all[i])
		}
	}
}

// TestMLDSA87_Tampered confirms tampered signatures are rejected.
func TestMLDSA87_Tampered(t *testing.T) {
	const n = 16
	pubs, msgs, sigs := genBatch87(t, n)

	sigs[2] = append([]byte(nil), sigs[2]...)
	sigs[2][len(sigs[2])-1] ^= 0xAA

	prev := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prev)

	all := BatchVerify(pubs, msgs, sigs)
	if all[2] {
		t.Fatalf("BatchVerify accepted tampered signature at[2]")
	}
	for i := 0; i < n; i++ {
		if i == 2 {
			continue
		}
		if !all[i] {
			t.Fatalf("BatchVerify rejected valid signature at[%d]", i)
		}
	}
}

// TestMLDSA87_BatchSign_RoundTrip exercises the BatchSign + verify cycle
// for the L5 parameter set.
func TestMLDSA87_BatchSign_RoundTrip(t *testing.T) {
	n := concurrentBatchThreshold + 2
	privs := make([]*PrivateKey, n)
	msgs := make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := GenerateKey(rand.Reader, MLDSA87)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		privs[i] = priv
		msgs[i] = []byte(fmt.Sprintf("mldsa87-roundtrip-%d", i))
	}

	sigs, err := BatchSign(rand.Reader, privs, msgs)
	if err != nil {
		t.Fatalf("BatchSign: %v", err)
	}
	for i := 0; i < n; i++ {
		if len(sigs[i]) != MLDSA87SignatureSize {
			t.Fatalf("sigs[%d] size: got %d, want %d", i, len(sigs[i]), MLDSA87SignatureSize)
		}
		if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
			t.Fatalf("Verify[%d] of batch-signed signature failed", i)
		}
	}
}

// BenchmarkMLDSA87_BatchVerify measures throughput at the L5 tier — the
// most expensive ML-DSA verify (~2.5x ML-DSA-65 cost).
func BenchmarkMLDSA87_BatchVerify(b *testing.B) {
	for _, size := range []int{1, 8, 32, 64} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			pubs, msgs, sigs := genBatch87(b, size)
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
