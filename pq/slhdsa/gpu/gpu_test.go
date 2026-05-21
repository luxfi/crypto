// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
	"github.com/luxfi/crypto/slhdsa"
)

// genSign192f builds n SLH-DSA-SHA2-192f keypairs + distinct messages ready
// for SignBatch. 192f is the canonical Magnetar profile.
func genSign192f(t testing.TB, n int) (privs []*slhdsa.PrivateKey, msgs [][]byte) {
	t.Helper()
	privs = make([]*slhdsa.PrivateKey, n)
	msgs = make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192f)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		privs[i] = priv
		msgs[i] = []byte(fmt.Sprintf("pq-slhdsa-gpu-msg-%d", i))
	}
	return
}

// TestParamsCatalogue pins the FIPS 205 §10 parameter table. Sizes are the
// FIPS 205 fixed catalogue values and must agree with the canonical
// crypto/slhdsa package's GetPublicKeySize / GetPrivateKeySize /
// GetSignatureSize accessors. This is a "two implementations of the same
// constant must agree" cross-check — if either side drifts, the FIPS 205
// conformance is broken.
func TestParamsCatalogue(t *testing.T) {
	type sizes struct{ pk, sk, sig int }
	wants := map[Mode]sizes{
		ModeSHA2_128s: {32, 64, 7856}, ModeSHAKE_128s: {32, 64, 7856},
		ModeSHA2_128f: {32, 64, 17088}, ModeSHAKE_128f: {32, 64, 17088},
		ModeSHA2_192s: {48, 96, 16224}, ModeSHAKE_192s: {48, 96, 16224},
		ModeSHA2_192f: {48, 96, 35664}, ModeSHAKE_192f: {48, 96, 35664},
		ModeSHA2_256s: {64, 128, 29792}, ModeSHAKE_256s: {64, 128, 29792},
		ModeSHA2_256f: {64, 128, 49856}, ModeSHAKE_256f: {64, 128, 49856},
	}

	for _, m := range AllModes() {
		p, ok := ParamsFor(m)
		if !ok {
			t.Fatalf("ParamsFor(%s) returned !ok", m)
		}
		want := wants[m]
		if p.PublicKeySize != want.pk || p.PrivateKeySize != want.sk || p.SignatureSize != want.sig {
			t.Fatalf("%s sizes: got pk=%d sk=%d sig=%d, want pk=%d sk=%d sig=%d",
				m, p.PublicKeySize, p.PrivateKeySize, p.SignatureSize,
				want.pk, want.sk, want.sig)
		}

		// Cross-check against the canonical slhdsa package's accessors.
		canon, err := modeToCanonical(m)
		if err != nil {
			t.Fatalf("modeToCanonical(%s): %v", m, err)
		}
		if got := slhdsa.GetPublicKeySize(canon); got != p.PublicKeySize {
			t.Fatalf("%s pk-size drift: gpu=%d canonical=%d", m, p.PublicKeySize, got)
		}
		if got := slhdsa.GetPrivateKeySize(canon); got != p.PrivateKeySize {
			t.Fatalf("%s sk-size drift: gpu=%d canonical=%d", m, p.PrivateKeySize, got)
		}
		if got := slhdsa.GetSignatureSize(canon); got != p.SignatureSize {
			t.Fatalf("%s sig-size drift: gpu=%d canonical=%d", m, p.SignatureSize, got)
		}

		// FIPS 205 §10: PublicKeySize = 2*N, PrivateKeySize = 4*N.
		if p.PublicKeySize != 2*p.N {
			t.Fatalf("%s: PublicKeySize=%d should equal 2*N=%d", m, p.PublicKeySize, 2*p.N)
		}
		if p.PrivateKeySize != 4*p.N {
			t.Fatalf("%s: PrivateKeySize=%d should equal 4*N=%d", m, p.PrivateKeySize, 4*p.N)
		}
		// FIPS 205 §10: H = D * HPrime.
		if p.H != p.D*p.HPrime {
			t.Fatalf("%s: H=%d should equal D*HPrime=%d*%d=%d", m, p.H, p.D, p.HPrime, p.D*p.HPrime)
		}
		// FIPS 205 §10: w = 16, so LgW = 4.
		if p.LgW != WOTSWBits {
			t.Fatalf("%s: LgW=%d should equal WOTSWBits=%d", m, p.LgW, WOTSWBits)
		}
		// FORS height and hypertree layers must be inside the FIPS 205 envelope.
		if p.A < FORSHeightMin || p.A > FORSHeightMax {
			t.Fatalf("%s: A=%d outside [%d,%d]", m, p.A, FORSHeightMin, FORSHeightMax)
		}
		if p.D < HypertreeLayersMin || p.D > HypertreeLayersMax {
			t.Fatalf("%s: D=%d outside [%d,%d]", m, p.D, HypertreeLayersMin, HypertreeLayersMax)
		}
	}

	// Magnetar profile pin.
	if CanonicalMagnetar != ModeSHA2_192f {
		t.Fatalf("CanonicalMagnetar = %s, want SLH-DSA-SHA2-192f", CanonicalMagnetar)
	}
}

// TestFastModesGated checks the IsFast / FastModes pair. The 'f' variants
// are the only ones the GPU substrate batches; 's' variants stay CPU-only.
// If this drifts, the dispatch ladder will silently sign 's' variants on
// the CPU when the operator asked for 'f' throughput.
func TestFastModesGated(t *testing.T) {
	fastSet := make(map[Mode]bool, len(FastModes()))
	for _, m := range FastModes() {
		fastSet[m] = true
		if !m.IsFast() {
			t.Fatalf("%s in FastModes but IsFast()=false", m)
		}
	}
	for _, m := range AllModes() {
		if fastSet[m] != m.IsFast() {
			t.Fatalf("%s IsFast=%v vs FastModes membership=%v", m, m.IsFast(), fastSet[m])
		}
	}
}

// TestModeToCanonicalRoundTrip pins that every gpu.Mode in AllModes() has a
// canonical slhdsa.Mode counterpart, and that the canonical wrapper's sizes
// agree with the parameter table.
func TestModeToCanonicalRoundTrip(t *testing.T) {
	for _, m := range AllModes() {
		canon, err := modeToCanonical(m)
		if err != nil {
			t.Fatalf("modeToCanonical(%s): %v", m, err)
		}
		p, _ := ParamsFor(m)
		if got := slhdsa.GetPublicKeySize(canon); got != p.PublicKeySize {
			t.Fatalf("%s: gpu PublicKeySize=%d, canonical=%d", m, p.PublicKeySize, got)
		}
	}
}

// TestSignBatch_RoundTrip pins the contract that the table-driven SignBatch
// wrapper produces signatures that the canonical verify accepts. This is
// the most important invariant: a wrapper that compiles but produces sigs
// the network rejects is worse than one that fails loudly.
func TestSignBatch_RoundTrip(t *testing.T) {
	const n = 4 // small batch — 192f sign is ~1.6s/sig on M1 Max
	privs, msgs := genSign192f(t, n)

	sigs, err := SignBatch(rand.Reader, ModeSHA2_192f, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch: %v", err)
	}
	if len(sigs) != n {
		t.Fatalf("SignBatch returned %d sigs, want %d", len(sigs), n)
	}

	pubs := make([]*slhdsa.PublicKey, n)
	for i := range privs {
		pubs[i] = privs[i].PublicKey
	}
	results, err := VerifyBatch(ModeSHA2_192f, pubs, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatch: %v", err)
	}
	for i, ok := range results {
		if !ok {
			t.Fatalf("VerifyBatch[%d] rejected a signature produced by SignBatch — sign/verify path corrupted", i)
		}
	}
}

// TestSignBatch_Determinism pins FIPS 205 SignDeterministic's no-randomness
// invariant: two SignBatch calls on the same (sk, msg) must produce byte-
// identical signatures. Catches PRF-state leakage and worker-ordering races
// in the parallel sign path.
func TestSignBatch_Determinism(t *testing.T) {
	const n = 3
	privs, msgs := genSign192f(t, n)

	first, err := SignBatch(rand.Reader, ModeSHA2_192f, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch first: %v", err)
	}
	second, err := SignBatch(rand.Reader, ModeSHA2_192f, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch second: %v", err)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(first[i], second[i]) {
			t.Fatalf("sig[%d] differs across two SignBatch calls — FIPS 205 determinism broken", i)
		}
	}
}

// TestSignBatch_GPU_Path forces the GPU dispatch tier. When no plugin is
// loaded, this exercises the goroutine-parallel CPU fallback. Either way
// the produced signatures MUST verify under the CPU oracle.
func TestSignBatch_GPU_Path(t *testing.T) {
	const n = 4
	privs, msgs := genSign192f(t, n)

	prev := backend.Default()
	backend.SetDefault(backend.GPU)
	defer backend.SetDefault(prev)

	sigs, err := SignBatch(rand.Reader, ModeSHA2_192f, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch: %v", err)
	}
	t.Logf("backend=%s gpuhost.Available=%v sig_count=%d sig_size=%d",
		backend.Default(), gpuhost.Available(), len(sigs), len(sigs[0]))

	for i := range sigs {
		if !privs[i].PublicKey.VerifySignature(msgs[i], sigs[i]) {
			t.Fatalf("CPU verify[%d] rejected a batch-signed signature — dispatch path corrupted", i)
		}
	}
}

// TestSignBatch_UnknownMode rejects values outside the FIPS 205 §10
// catalogue. Must not panic.
func TestSignBatch_UnknownMode(t *testing.T) {
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192f)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, err = SignBatch(rand.Reader, Mode(99), []*slhdsa.PrivateKey{priv}, [][]byte{[]byte("x")})
	if err == nil {
		t.Fatalf("SignBatch(invalid mode) returned nil error")
	}
}

// TestSignBatch_EmptyBatch is the zero-batch boundary case.
func TestSignBatch_EmptyBatch(t *testing.T) {
	sigs, err := SignBatch(rand.Reader, ModeSHA2_192f, nil, nil)
	if err != nil {
		t.Fatalf("SignBatch(empty): %v", err)
	}
	if len(sigs) != 0 {
		t.Fatalf("SignBatch(empty) returned %d sigs, want 0", len(sigs))
	}
}

// TestVerifyBatch_TamperRejected pins that a bit-flipped signature is
// rejected. Catches the worst-case GPU bug: silently accepting everything.
func TestVerifyBatch_TamperRejected(t *testing.T) {
	const n = 3
	privs, msgs := genSign192f(t, n)
	pubs := make([]*slhdsa.PublicKey, n)
	for i := range privs {
		pubs[i] = privs[i].PublicKey
	}

	sigs, err := SignBatch(rand.Reader, ModeSHA2_192f, privs, msgs)
	if err != nil {
		t.Fatalf("SignBatch: %v", err)
	}

	// Tamper signature[1].
	tampered := append([]byte(nil), sigs[1]...)
	tampered[0] ^= 0xAA
	sigs[1] = tampered

	results, err := VerifyBatch(ModeSHA2_192f, pubs, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatch: %v", err)
	}
	if results[1] {
		t.Fatalf("VerifyBatch accepted a bit-flipped signature — verify is broken")
	}
	if !results[0] || !results[2] {
		t.Fatalf("VerifyBatch rejected unrelated signatures: %v", results)
	}
}

// BenchmarkSignBatch_Serial measures the per-element CPU sign cost on
// SLH-DSA-SHA2-192f as the baseline for the parallel speedup calculation.
func BenchmarkSignBatch_Serial(b *testing.B) {
	const batchSize = 1
	privs, msgs := genSign192f(b, batchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := privs[0].SignCtx(rand.Reader, msgs[0], nil); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

// BenchmarkSignBatch_Parallel measures the parallel dispatch across batch
// sizes. n=21 is the Lux production quorum size; n=32 saturates GOMAXPROCS
// on a typical validator host.
func BenchmarkSignBatch_Parallel(b *testing.B) {
	for _, size := range []int{1, 32} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			privs, msgs := genSign192f(b, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigs, err := SignBatch(rand.Reader, ModeSHA2_192f, privs, msgs)
				if err != nil {
					b.Fatalf("SignBatch: %v", err)
				}
				if len(sigs) != size {
					b.Fatalf("len(sigs)=%d want %d", len(sigs), size)
				}
			}
		})
	}
}
