// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
	"testing"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// -----------------------------------------------------------------------------
// Parameter table sanity
// -----------------------------------------------------------------------------

// TestParams_FIPS204Sizes checks the parameter table against FIPS 204 §4
// Table 1 sizes. Any drift here breaks every downstream caller; this is
// the canonical sanity gate.
func TestParams_FIPS204Sizes(t *testing.T) {
	want := []struct {
		mode  Mode
		pk    int
		sk    int
		sig   int
		k, l  int
		eta   int
		tau   int
		gamma int // gamma1Bits
	}{
		{ModeMLDSA44, 1312, 2560, 2420, 4, 4, 2, 39, 17},
		{ModeMLDSA65, 1952, 4032, 3309, 6, 5, 4, 49, 19},
		{ModeMLDSA87, 2592, 4896, 4627, 8, 7, 2, 60, 19},
	}
	for _, w := range want {
		p, ok := ParamsFor(w.mode)
		if !ok {
			t.Fatalf("ParamsFor(%v) returned !ok", w.mode)
		}
		if p.PublicKeySize != w.pk {
			t.Errorf("%v: PublicKeySize=%d, want %d", w.mode, p.PublicKeySize, w.pk)
		}
		if p.PrivateKeySize != w.sk {
			t.Errorf("%v: PrivateKeySize=%d, want %d", w.mode, p.PrivateKeySize, w.sk)
		}
		if p.SignatureSize != w.sig {
			t.Errorf("%v: SignatureSize=%d, want %d", w.mode, p.SignatureSize, w.sig)
		}
		if p.K != w.k || p.L != w.l {
			t.Errorf("%v: (K,L)=(%d,%d), want (%d,%d)", w.mode, p.K, p.L, w.k, w.l)
		}
		if p.Eta != w.eta {
			t.Errorf("%v: Eta=%d, want %d", w.mode, p.Eta, w.eta)
		}
		if p.Tau != w.tau {
			t.Errorf("%v: Tau=%d, want %d", w.mode, p.Tau, w.tau)
		}
		if p.Gamma1Bits != w.gamma {
			t.Errorf("%v: Gamma1Bits=%d, want %d", w.mode, p.Gamma1Bits, w.gamma)
		}
	}
}

// TestParams_CrossCheckWithCircl asserts that the local parameter table
// matches the cloudflare/circl wrappers byte-for-byte. If circl ever
// bumps a constant the test catches the drift before it hits production.
func TestParams_CrossCheckWithCircl(t *testing.T) {
	p44 := MustParamsFor(ModeMLDSA44)
	if p44.PublicKeySize != mldsa44.PublicKeySize ||
		p44.PrivateKeySize != mldsa44.PrivateKeySize ||
		p44.SignatureSize != mldsa44.SignatureSize {
		t.Errorf("ML-DSA-44 size mismatch with circl: local=(%d,%d,%d) circl=(%d,%d,%d)",
			p44.PublicKeySize, p44.PrivateKeySize, p44.SignatureSize,
			mldsa44.PublicKeySize, mldsa44.PrivateKeySize, mldsa44.SignatureSize)
	}
	p65 := MustParamsFor(ModeMLDSA65)
	if p65.PublicKeySize != mldsa65.PublicKeySize ||
		p65.PrivateKeySize != mldsa65.PrivateKeySize ||
		p65.SignatureSize != mldsa65.SignatureSize {
		t.Errorf("ML-DSA-65 size mismatch with circl: local=(%d,%d,%d) circl=(%d,%d,%d)",
			p65.PublicKeySize, p65.PrivateKeySize, p65.SignatureSize,
			mldsa65.PublicKeySize, mldsa65.PrivateKeySize, mldsa65.SignatureSize)
	}
	p87 := MustParamsFor(ModeMLDSA87)
	if p87.PublicKeySize != mldsa87.PublicKeySize ||
		p87.PrivateKeySize != mldsa87.PrivateKeySize ||
		p87.SignatureSize != mldsa87.SignatureSize {
		t.Errorf("ML-DSA-87 size mismatch with circl: local=(%d,%d,%d) circl=(%d,%d,%d)",
			p87.PublicKeySize, p87.PrivateKeySize, p87.SignatureSize,
			mldsa87.PublicKeySize, mldsa87.PrivateKeySize, mldsa87.SignatureSize)
	}
}

// TestParams_InvalidMode confirms an unknown mode yields !ok.
func TestParams_InvalidMode(t *testing.T) {
	if _, ok := ParamsFor(Mode(7)); ok {
		t.Fatal("ParamsFor(7) returned ok=true; want false")
	}
}

// -----------------------------------------------------------------------------
// NTT correctness
// -----------------------------------------------------------------------------

// TestNTT_Roundtrip is the headline KAT-style test: for random
// polynomials over R_q, INTT(NTT(p)) == p coefficient-for-coefficient.
// This is the primary guarantee that the FIPS 204 NTT is correctly
// implemented — any twiddle table drift, missing reduction, or
// off-by-one bit-reverse failure breaks this.
func TestNTT_Roundtrip(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(42, 0xDA1A))
	const iterations = 256
	for it := 0; it < iterations; it++ {
		var orig, p [N]uint32
		for i := 0; i < N; i++ {
			orig[i] = uint32(rng.Uint64()) % Q
		}
		p = orig
		NTTForwardCPU(&p)
		NTTInverseCPU(&p)
		for i := 0; i < N; i++ {
			if p[i] != orig[i] {
				t.Fatalf("iter %d: NTT∘INTT mismatch at index %d: got %d, want %d",
					it, i, p[i], orig[i])
			}
		}
	}
}

// TestNTT_Linearity confirms NTT(a + b) == NTT(a) + NTT(b) componentwise
// modulo Q. This is a structural property of the linear NTT operator
// and a strong sanity check independent of the twiddle table.
func TestNTT_Linearity(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(0xBEEF, 1))
	const iterations = 32
	for it := 0; it < iterations; it++ {
		var a, b, sum, aNTT, bNTT, sumNTT [N]uint32
		for i := 0; i < N; i++ {
			a[i] = uint32(rng.Uint64()) % Q
			b[i] = uint32(rng.Uint64()) % Q
			sum[i] = addModQ(a[i], b[i])
		}
		aNTT = a
		bNTT = b
		sumNTT = sum
		NTTForwardCPU(&aNTT)
		NTTForwardCPU(&bNTT)
		NTTForwardCPU(&sumNTT)
		for i := 0; i < N; i++ {
			want := addModQ(aNTT[i], bNTT[i])
			if sumNTT[i] != want {
				t.Fatalf("iter %d: linearity broken at %d: NTT(a+b)=%d, NTT(a)+NTT(b)=%d",
					it, i, sumNTT[i], want)
			}
		}
	}
}

// TestNTT_KnownVector exercises one fixed input/output pair: NTT of the
// constant polynomial p(X)=1 must produce the all-ones evaluation in
// NTT domain (since p(ζ^k) = 1 for every k). This guards against
// catastrophic table errors that would still pass the roundtrip test.
func TestNTT_KnownVector(t *testing.T) {
	var p [N]uint32
	p[0] = 1 // p(X) = 1
	NTTForwardCPU(&p)
	for i := 0; i < N; i++ {
		if p[i] != 1 {
			t.Fatalf("NTT(1) evaluation %d = %d, want 1", i, p[i])
		}
	}
}

// TestPolyMul_AgainstSchoolbook checks PolyMulCPU against a slow
// schoolbook reference for random small-degree inputs. Multiplication
// in R_q = Z_q[X]/(X^N+1) is negacyclic: the wrap-around term gets a
// minus sign.
func TestPolyMul_AgainstSchoolbook(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(0xC0FFEE, 0))
	const iterations = 8 // schoolbook is O(N^2), keep tight
	for it := 0; it < iterations; it++ {
		var a, b [N]uint32
		for i := 0; i < N; i++ {
			a[i] = uint32(rng.Uint64()) % Q
			b[i] = uint32(rng.Uint64()) % Q
		}
		got := PolyMulCPU(&a, &b)
		want := schoolbookMul(&a, &b)
		for i := 0; i < N; i++ {
			if got[i] != want[i] {
				t.Fatalf("iter %d: PolyMul mismatch at %d: got %d, want %d",
					it, i, got[i], want[i])
			}
		}
	}
}

// schoolbookMul computes a * b in R_q = Z_q[X]/(X^N+1) using the naive
// O(N^2) algorithm. Used as a known-correct reference for PolyMul tests.
func schoolbookMul(a, b *[N]uint32) [N]uint32 {
	var out [N]uint32
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			k := i + j
			prod := uint32((uint64(a[i]) * uint64(b[j])) % uint64(Q))
			if k < N {
				out[k] = addModQ(out[k], prod)
			} else {
				// X^N = -1, so coefficient at position k-N gets subtracted.
				out[k-N] = subModQ(out[k-N], prod)
			}
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Constant-time arithmetic helpers
// -----------------------------------------------------------------------------

// TestReduce32_Bounds checks that reduce32 produces values in [0, Q)
// for a representative sample of inputs across the uint32 range.
func TestReduce32_Bounds(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(0xBA5E, 0))
	for i := 0; i < 10000; i++ {
		a := uint32(rng.Uint64())
		r := reduce32(a)
		if r >= Q {
			t.Fatalf("reduce32(%d) = %d, out of bounds [0, %d)", a, r, Q)
		}
		if uint64(r) != uint64(a)%uint64(Q) {
			t.Fatalf("reduce32(%d) = %d, want %d", a, r, uint32(uint64(a)%uint64(Q)))
		}
	}
}

// TestAddSubMod_Bounds exercises addModQ / subModQ around the boundary.
func TestAddSubMod_Bounds(t *testing.T) {
	tests := []struct {
		a, b   uint32
		wantA  uint32 // addModQ(a,b)
		wantS  uint32 // subModQ(a,b)
	}{
		{0, 0, 0, 0},
		{Q - 1, 1, 0, Q - 2},
		{Q - 1, Q - 1, Q - 2, 0},
		{1, 2, 3, Q - 1},
		{12345, 67890, 80235, Q - (67890 - 12345)},
	}
	for _, tt := range tests {
		if g := addModQ(tt.a, tt.b); g != tt.wantA {
			t.Errorf("addModQ(%d, %d) = %d, want %d", tt.a, tt.b, g, tt.wantA)
		}
		if g := subModQ(tt.a, tt.b); g != tt.wantS {
			t.Errorf("subModQ(%d, %d) = %d, want %d", tt.a, tt.b, g, tt.wantS)
		}
	}
}

// -----------------------------------------------------------------------------
// Batch accelerator
// -----------------------------------------------------------------------------

// TestAccelerator_Available simply exercises the API; both true and
// false outcomes are valid depending on the host.
func TestAccelerator_Available(t *testing.T) {
	a := GetAccelerator()
	if a == nil {
		t.Fatal("GetAccelerator() returned nil")
	}
	_ = a.Available()
	if Backend() == "" {
		t.Fatal("Backend() returned empty string")
	}
}

// TestAccelerator_NTTBatch_Identity confirms that the batch dispatcher
// produces the same per-polynomial output as the single-poly path,
// regardless of which engine is selected.
func TestAccelerator_NTTBatch_Identity(t *testing.T) {
	const batch = 32 // exceeds the default GPU threshold
	rng := mrand.New(mrand.NewPCG(0xFADE, 0xC0DE))
	polys := make([]*[N]uint32, batch)
	cpuRef := make([][N]uint32, batch)
	for i := range polys {
		var p [N]uint32
		for j := 0; j < N; j++ {
			p[j] = uint32(rng.Uint64()) % Q
		}
		cpuRef[i] = p
		NTTForwardCPU(&cpuRef[i])
		dup := p
		polys[i] = &dup
	}

	a := GetAccelerator()
	if err := a.NTTForwardBatch(polys); err != nil {
		t.Fatalf("NTTForwardBatch: %v", err)
	}
	for i := range polys {
		if *polys[i] != cpuRef[i] {
			t.Fatalf("batch[%d]: GPU/CPU result differs at index 0: got %d, want %d",
				i, polys[i][0], cpuRef[i][0])
		}
	}
}

// TestAccelerator_InverseRoundtrip drives the batch dispatcher through
// NTT→INTT and confirms element-wise equality with the input.
func TestAccelerator_InverseRoundtrip(t *testing.T) {
	const batch = 24
	rng := mrand.New(mrand.NewPCG(0x1234, 0x5678))
	polys := make([]*[N]uint32, batch)
	orig := make([][N]uint32, batch)
	for i := range polys {
		var p [N]uint32
		for j := 0; j < N; j++ {
			p[j] = uint32(rng.Uint64()) % Q
		}
		orig[i] = p
		dup := p
		polys[i] = &dup
	}
	a := GetAccelerator()
	if err := a.NTTForwardBatch(polys); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if err := a.NTTInverseBatch(polys); err != nil {
		t.Fatalf("inverse: %v", err)
	}
	for i := range polys {
		if *polys[i] != orig[i] {
			t.Fatalf("batch[%d]: NTT∘INTT not identity", i)
		}
	}
}

// TestAccelerator_PolyMulBatch checks the batched multiplication path.
func TestAccelerator_PolyMulBatch(t *testing.T) {
	const batch = 20
	rng := mrand.New(mrand.NewPCG(0xA1B2, 0xC3D4))
	a := make([]*[N]uint32, batch)
	b := make([]*[N]uint32, batch)
	c := make([]*[N]uint32, batch)
	ref := make([][N]uint32, batch)
	for i := 0; i < batch; i++ {
		var aPoly, bPoly, cPoly [N]uint32
		for j := 0; j < N; j++ {
			aPoly[j] = uint32(rng.Uint64()) % Q
			bPoly[j] = uint32(rng.Uint64()) % Q
		}
		ref[i] = PolyMulCPU(&aPoly, &bPoly)
		a[i] = &aPoly
		b[i] = &bPoly
		c[i] = &cPoly
	}
	acc := GetAccelerator()
	if err := acc.PolyMulBatch(a, b, c); err != nil {
		t.Fatalf("PolyMulBatch: %v", err)
	}
	for i := 0; i < batch; i++ {
		if *c[i] != ref[i] {
			t.Fatalf("batch[%d]: PolyMulBatch result differs from CPU reference", i)
		}
	}
}

// TestAccelerator_Shapes verifies the shape-mismatch errors.
func TestAccelerator_Shapes(t *testing.T) {
	a := GetAccelerator()
	one := new([N]uint32)
	if err := a.PolyMulBatch([]*[N]uint32{one}, nil, nil); err != ErrShapeMismatch {
		t.Errorf("PolyMulBatch with shape mismatch: got %v, want ErrShapeMismatch", err)
	}
	if err := a.SignBatch(ModeMLDSA65, [][]byte{[]byte("x")}, nil, nil); err != ErrShapeMismatch {
		t.Errorf("SignBatch with shape mismatch: got %v, want ErrShapeMismatch", err)
	}
	if _, err := a.VerifyBatch(Mode(7), nil, nil, nil); err != ErrInvalidMode {
		t.Errorf("VerifyBatch with invalid mode: got %v, want ErrInvalidMode", err)
	}
}

// TestAccelerator_Stats checks the GPU/CPU dispatch counters move.
func TestAccelerator_Stats(t *testing.T) {
	a := newAccelerator()
	gpu0, cpu0 := a.Stats()
	one := new([N]uint32)
	a.NTTForward(one)
	gpu1, cpu1 := a.Stats()
	if cpu1 != cpu0+1 {
		t.Errorf("NTTForward did not increment CPU counter: got %d, want %d", cpu1, cpu0+1)
	}
	if gpu1 != gpu0 {
		t.Errorf("NTTForward should not bump GPU counter: got %d, want %d", gpu1, gpu0)
	}
}

// TestAccelerator_ThresholdRouting forces a small batch (below threshold)
// and verifies the dispatcher stays on the CPU. This is the threshold-
// routing pattern in action.
func TestAccelerator_ThresholdRouting(t *testing.T) {
	a := newAccelerator()
	a.SetThresholds(1000, 1000, 1000) // never dispatch to GPU
	const batch = 4
	polys := make([]*[N]uint32, batch)
	for i := range polys {
		var p [N]uint32
		for j := 0; j < N; j++ {
			p[j] = uint32(j) % Q
		}
		polys[i] = &p
	}
	g0, c0 := a.Stats()
	if err := a.NTTForwardBatch(polys); err != nil {
		t.Fatalf("NTTForwardBatch: %v", err)
	}
	g1, c1 := a.Stats()
	if g1 != g0 {
		t.Errorf("threshold gate failed: GPU counter incremented: %d -> %d", g0, g1)
	}
	if c1 != c0+batch {
		t.Errorf("CPU counter not incremented by %d: %d -> %d", batch, c0, c1)
	}
}

// -----------------------------------------------------------------------------
// FIPS 204 KAT integration via SignBatch / VerifyBatch
// -----------------------------------------------------------------------------

// TestAccelerator_SignVerify_AllModes runs an end-to-end batch sign +
// batch verify across all three FIPS 204 modes. The signatures and
// public keys come from the standard mldsa wrappers (circl-backed) so
// any divergence in the accelerator's framing surfaces as a verify
// failure here.
func TestAccelerator_SignVerify_AllModes(t *testing.T) {
	for _, mode := range AllModes() {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			runSignVerifyBatch(t, mode, 4)
		})
	}
}

// TestAccelerator_SignVerify_AboveThreshold runs at a batch size above
// the default sign threshold to exercise the GPU path when available.
// CPU and GPU produce identical accept/reject results.
func TestAccelerator_SignVerify_AboveThreshold(t *testing.T) {
	for _, mode := range AllModes() {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			runSignVerifyBatch(t, mode, 17) // > thrSign && > thrVrfy
		})
	}
}

func runSignVerifyBatch(t *testing.T, mode Mode, batch int) {
	t.Helper()
	p := MustParamsFor(mode)

	msgs := make([][]byte, batch)
	sks := make([][]byte, batch)
	pks := make([][]byte, batch)
	sigs := make([][]byte, batch)
	for i := 0; i < batch; i++ {
		var pk, sk []byte
		var err error
		switch mode {
		case ModeMLDSA44:
			pubKey, privKey, gerr := mldsa44.GenerateKey(rand.Reader)
			if gerr != nil {
				t.Fatalf("mldsa44 GenerateKey: %v", gerr)
			}
			pk, err = pubKey.MarshalBinary()
			if err != nil {
				t.Fatalf("pk marshal: %v", err)
			}
			sk, err = privKey.MarshalBinary()
			if err != nil {
				t.Fatalf("sk marshal: %v", err)
			}
		case ModeMLDSA65:
			pubKey, privKey, gerr := mldsa65.GenerateKey(rand.Reader)
			if gerr != nil {
				t.Fatalf("mldsa65 GenerateKey: %v", gerr)
			}
			pk, err = pubKey.MarshalBinary()
			if err != nil {
				t.Fatalf("pk marshal: %v", err)
			}
			sk, err = privKey.MarshalBinary()
			if err != nil {
				t.Fatalf("sk marshal: %v", err)
			}
		case ModeMLDSA87:
			pubKey, privKey, gerr := mldsa87.GenerateKey(rand.Reader)
			if gerr != nil {
				t.Fatalf("mldsa87 GenerateKey: %v", gerr)
			}
			pk, err = pubKey.MarshalBinary()
			if err != nil {
				t.Fatalf("pk marshal: %v", err)
			}
			sk, err = privKey.MarshalBinary()
			if err != nil {
				t.Fatalf("sk marshal: %v", err)
			}
		}
		var msg [16]byte
		if _, err := rand.Read(msg[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		binary.LittleEndian.PutUint64(msg[:8], uint64(i))
		msgs[i] = msg[:]
		sks[i] = sk
		pks[i] = pk
		sigs[i] = make([]byte, p.SignatureSize)
	}

	a := GetAccelerator()
	if err := a.SignBatch(mode, msgs, sks, sigs); err != nil {
		t.Fatalf("SignBatch: %v", err)
	}
	for i, s := range sigs {
		if len(s) != p.SignatureSize {
			t.Errorf("sigs[%d] wrong length: got %d, want %d", i, len(s), p.SignatureSize)
		}
		if isZeroBytes(s) {
			t.Errorf("sigs[%d] is all-zero — signing failed silently", i)
		}
	}
	ok, err := a.VerifyBatch(mode, msgs, sigs, pks)
	if err != nil {
		t.Fatalf("VerifyBatch: %v", err)
	}
	for i, v := range ok {
		if !v {
			t.Errorf("verify[%d] = false; expected accept", i)
		}
	}

	// Negative test: flip one bit in one signature and expect a single
	// rejection. Verify is constant-time per FIPS 204 §5.3 so all other
	// signatures must remain accept.
	if len(sigs) > 0 && len(sigs[0]) > 0 {
		flipped := make([]byte, len(sigs[0]))
		copy(flipped, sigs[0])
		flipped[0] ^= 0xFF
		bad := make([][]byte, len(sigs))
		copy(bad, sigs)
		bad[0] = flipped
		ok2, err := a.VerifyBatch(mode, msgs, bad, pks)
		if err != nil {
			t.Fatalf("VerifyBatch (corrupt): %v", err)
		}
		if ok2[0] {
			t.Error("verify[0] accepted a corrupted signature")
		}
		for i := 1; i < len(ok2); i++ {
			if !ok2[i] {
				t.Errorf("verify[%d] rejected after sig[0] corruption", i)
			}
		}
	}
}

// TestAccelerator_CrossWrapperEquivalence asserts that the accelerator
// path produces signatures that the plain mldsa{44,65,87}.Verify function
// will accept — proving the accelerator and the standard wrappers agree
// on the same FIPS 204 wire format.
func TestAccelerator_CrossWrapperEquivalence(t *testing.T) {
	for _, mode := range AllModes() {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			p := MustParamsFor(mode)

			const batch = 5
			msgs := make([][]byte, batch)
			sks := make([][]byte, batch)
			pks := make([][]byte, batch)
			sigs := make([][]byte, batch)
			pubKeys := make([]any, batch)

			for i := 0; i < batch; i++ {
				msgs[i] = []byte("cross-wrapper-eq test " + string(rune('A'+i)))
				switch mode {
				case ModeMLDSA44:
					pk, sk, _ := mldsa44.GenerateKey(rand.Reader)
					sks[i], _ = sk.MarshalBinary()
					pks[i], _ = pk.MarshalBinary()
					pubKeys[i] = pk
				case ModeMLDSA65:
					pk, sk, _ := mldsa65.GenerateKey(rand.Reader)
					sks[i], _ = sk.MarshalBinary()
					pks[i], _ = pk.MarshalBinary()
					pubKeys[i] = pk
				case ModeMLDSA87:
					pk, sk, _ := mldsa87.GenerateKey(rand.Reader)
					sks[i], _ = sk.MarshalBinary()
					pks[i], _ = pk.MarshalBinary()
					pubKeys[i] = pk
				}
				sigs[i] = make([]byte, p.SignatureSize)
			}

			a := GetAccelerator()
			if err := a.SignBatch(mode, msgs, sks, sigs); err != nil {
				t.Fatalf("SignBatch: %v", err)
			}

			// Verify each signature via the standard (non-accelerator)
			// wrapper. The signature must be in canonical FIPS 204 wire
			// form for this to pass.
			for i := 0; i < batch; i++ {
				switch mode {
				case ModeMLDSA44:
					if !mldsa44.Verify(pubKeys[i].(*mldsa44.PublicKey), msgs[i], nil, sigs[i]) {
						t.Errorf("mldsa44.Verify[%d] rejected accelerator signature", i)
					}
				case ModeMLDSA65:
					if !mldsa65.Verify(pubKeys[i].(*mldsa65.PublicKey), msgs[i], nil, sigs[i]) {
						t.Errorf("mldsa65.Verify[%d] rejected accelerator signature", i)
					}
				case ModeMLDSA87:
					if !mldsa87.Verify(pubKeys[i].(*mldsa87.PublicKey), msgs[i], nil, sigs[i]) {
						t.Errorf("mldsa87.Verify[%d] rejected accelerator signature", i)
					}
				}
			}
		})
	}
}

// isZeroBytes returns true when every byte in b is 0.
func isZeroBytes(b []byte) bool {
	return len(b) > 0 && bytes.Equal(b, make([]byte, len(b)))
}

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkNTTForward_CPU(b *testing.B) {
	var p [N]uint32
	for i := 0; i < N; i++ {
		p[i] = uint32(i) % Q
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NTTForwardCPU(&p)
	}
}

func BenchmarkNTTInverse_CPU(b *testing.B) {
	var p [N]uint32
	for i := 0; i < N; i++ {
		p[i] = uint32(i) % Q
	}
	NTTForwardCPU(&p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var q [N]uint32 = p
		NTTInverseCPU(&q)
	}
}

func BenchmarkPolyMul_CPU(b *testing.B) {
	var x, y [N]uint32
	for i := 0; i < N; i++ {
		x[i] = uint32(i) % Q
		y[i] = uint32(i*7+3) % Q
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PolyMulCPU(&x, &y)
	}
}

func benchNTTBatch(b *testing.B, batch int) {
	a := GetAccelerator()
	polys := make([]*[N]uint32, batch)
	for i := range polys {
		var p [N]uint32
		for j := 0; j < N; j++ {
			p[j] = uint32(j+i) % Q
		}
		polys[i] = &p
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.NTTForwardBatch(polys); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNTTBatch_1(b *testing.B)  { benchNTTBatch(b, 1) }
func BenchmarkNTTBatch_16(b *testing.B) { benchNTTBatch(b, 16) }
func BenchmarkNTTBatch_64(b *testing.B) { benchNTTBatch(b, 64) }

func benchSignBatch(b *testing.B, mode Mode, batch int) {
	p := MustParamsFor(mode)
	msgs := make([][]byte, batch)
	sks := make([][]byte, batch)
	sigs := make([][]byte, batch)
	for i := 0; i < batch; i++ {
		msgs[i] = []byte("bench message")
		var sk []byte
		var err error
		switch mode {
		case ModeMLDSA44:
			_, privKey, gerr := mldsa44.GenerateKey(rand.Reader)
			if gerr != nil {
				b.Fatal(gerr)
			}
			sk, err = privKey.MarshalBinary()
		case ModeMLDSA65:
			_, privKey, gerr := mldsa65.GenerateKey(rand.Reader)
			if gerr != nil {
				b.Fatal(gerr)
			}
			sk, err = privKey.MarshalBinary()
		case ModeMLDSA87:
			_, privKey, gerr := mldsa87.GenerateKey(rand.Reader)
			if gerr != nil {
				b.Fatal(gerr)
			}
			sk, err = privKey.MarshalBinary()
		}
		if err != nil {
			b.Fatal(err)
		}
		sks[i] = sk
		sigs[i] = make([]byte, p.SignatureSize)
	}
	a := GetAccelerator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.SignBatch(mode, msgs, sks, sigs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignBatch_44_1(b *testing.B)  { benchSignBatch(b, ModeMLDSA44, 1) }
func BenchmarkSignBatch_44_16(b *testing.B) { benchSignBatch(b, ModeMLDSA44, 16) }
func BenchmarkSignBatch_44_64(b *testing.B) { benchSignBatch(b, ModeMLDSA44, 64) }

func BenchmarkSignBatch_65_1(b *testing.B)  { benchSignBatch(b, ModeMLDSA65, 1) }
func BenchmarkSignBatch_65_16(b *testing.B) { benchSignBatch(b, ModeMLDSA65, 16) }
func BenchmarkSignBatch_65_64(b *testing.B) { benchSignBatch(b, ModeMLDSA65, 64) }

func BenchmarkSignBatch_87_1(b *testing.B)  { benchSignBatch(b, ModeMLDSA87, 1) }
func BenchmarkSignBatch_87_16(b *testing.B) { benchSignBatch(b, ModeMLDSA87, 16) }
func BenchmarkSignBatch_87_64(b *testing.B) { benchSignBatch(b, ModeMLDSA87, 64) }

func benchVerifyBatch(b *testing.B, mode Mode, batch int) {
	p := MustParamsFor(mode)
	msgs := make([][]byte, batch)
	sks := make([][]byte, batch)
	pks := make([][]byte, batch)
	sigs := make([][]byte, batch)
	for i := 0; i < batch; i++ {
		msgs[i] = []byte("bench verify")
		var sk, pk []byte
		var err error
		switch mode {
		case ModeMLDSA44:
			pubKey, privKey, gerr := mldsa44.GenerateKey(rand.Reader)
			if gerr != nil {
				b.Fatal(gerr)
			}
			sk, err = privKey.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			pk, err = pubKey.MarshalBinary()
		case ModeMLDSA65:
			pubKey, privKey, gerr := mldsa65.GenerateKey(rand.Reader)
			if gerr != nil {
				b.Fatal(gerr)
			}
			sk, err = privKey.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			pk, err = pubKey.MarshalBinary()
		case ModeMLDSA87:
			pubKey, privKey, gerr := mldsa87.GenerateKey(rand.Reader)
			if gerr != nil {
				b.Fatal(gerr)
			}
			sk, err = privKey.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			pk, err = pubKey.MarshalBinary()
		}
		if err != nil {
			b.Fatal(err)
		}
		sks[i] = sk
		pks[i] = pk
		sigs[i] = make([]byte, p.SignatureSize)
	}
	a := GetAccelerator()
	if err := a.SignBatch(mode, msgs, sks, sigs); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.VerifyBatch(mode, msgs, sigs, pks); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyBatch_44_1(b *testing.B)  { benchVerifyBatch(b, ModeMLDSA44, 1) }
func BenchmarkVerifyBatch_44_16(b *testing.B) { benchVerifyBatch(b, ModeMLDSA44, 16) }
func BenchmarkVerifyBatch_44_64(b *testing.B) { benchVerifyBatch(b, ModeMLDSA44, 64) }

func BenchmarkVerifyBatch_65_1(b *testing.B)  { benchVerifyBatch(b, ModeMLDSA65, 1) }
func BenchmarkVerifyBatch_65_16(b *testing.B) { benchVerifyBatch(b, ModeMLDSA65, 16) }
func BenchmarkVerifyBatch_65_64(b *testing.B) { benchVerifyBatch(b, ModeMLDSA65, 64) }

func BenchmarkVerifyBatch_87_1(b *testing.B)  { benchVerifyBatch(b, ModeMLDSA87, 1) }
func BenchmarkVerifyBatch_87_16(b *testing.B) { benchVerifyBatch(b, ModeMLDSA87, 16) }
func BenchmarkVerifyBatch_87_64(b *testing.B) { benchVerifyBatch(b, ModeMLDSA87, 64) }
