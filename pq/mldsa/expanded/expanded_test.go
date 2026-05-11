// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package expanded

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// TestSizeConstants pins the wire layout sizes. If these values
// change, EVERY persisted expanded key on the network goes invalid —
// so the constants are deliberately spelled out as integer literals
// matching the documentation in doc.go and a regression here is
// almost certainly a bug.
func TestSizeConstants(t *testing.T) {
	cases := []struct {
		set      ParamSet
		expected int
	}{
		{MLDSA44, 11776},
		{MLDSA65, 22080},
		{MLDSA87, 41216},
	}
	for _, tc := range cases {
		_, _, _, got, ok := tc.set.params()
		if !ok {
			t.Fatalf("%s: params() returned !ok", tc.set)
		}
		if got != tc.expected {
			t.Errorf("%s: ExpandedASize=%d want %d", tc.set, got, tc.expected)
		}
	}

	// Cross-check the named constants match.
	if ExpandedASize44 != 11776 {
		t.Errorf("ExpandedASize44 = %d", ExpandedASize44)
	}
	if ExpandedASize65 != 22080 {
		t.Errorf("ExpandedASize65 = %d", ExpandedASize65)
	}
	if ExpandedASize87 != 41216 {
		t.Errorf("ExpandedASize87 = %d", ExpandedASize87)
	}
}

// TestPackRoundTrip confirms the 23-bit pack/unpack pair is
// lossless: every input coefficient < q survives a pack-then-unpack
// trip unchanged.
func TestPackRoundTrip(t *testing.T) {
	// A non-trivial test vector: increasing coefficients near 0 and
	// near q so we exercise the high bits of c[i] as well as the
	// inter-coefficient byte boundaries.
	var in [polyN]uint32
	for i := 0; i < polyN; i++ {
		// Deterministic, spread across the valid range.
		in[i] = uint32(i*131) % polyQ
	}
	var packed [polyPackedSize]byte
	packCoeffs(packed[:], &in)

	var out [polyN]uint32
	unpackCoeffs(&out, packed[:])

	for i := 0; i < polyN; i++ {
		if in[i] != out[i] {
			t.Fatalf("pack/unpack: coeff %d: in=%d out=%d", i, in[i], out[i])
		}
	}
}

// TestPackBoundary verifies pack/unpack on the extreme corners of
// the coefficient range: 0, 1, q−1. q−1 is the largest representable
// coefficient and exercises every bit position.
func TestPackBoundary(t *testing.T) {
	var in [polyN]uint32
	for i := 0; i < polyN; i++ {
		switch i % 3 {
		case 0:
			in[i] = 0
		case 1:
			in[i] = 1
		case 2:
			in[i] = polyQ - 1
		}
	}
	var packed [polyPackedSize]byte
	packCoeffs(packed[:], &in)
	var out [polyN]uint32
	unpackCoeffs(&out, packed[:])
	for i := 0; i < polyN; i++ {
		if in[i] != out[i] {
			t.Fatalf("boundary coeff %d: in=%d out=%d", i, in[i], out[i])
		}
	}
}

// TestRejSampleDeterministic confirms two independent calls with the
// same (rho, nonce) produce byte-identical polynomial coefficients —
// the headline property the expanded-form cache relies on.
func TestRejSampleDeterministic(t *testing.T) {
	var rho [32]byte
	for i := range rho {
		rho[i] = byte(i * 7)
	}
	var p1, p2 [polyN]uint32
	rejSampleNTTPoly(&p1, &rho, 0x0102)
	rejSampleNTTPoly(&p2, &rho, 0x0102)
	for i := 0; i < polyN; i++ {
		if p1[i] != p2[i] {
			t.Fatalf("nondeterministic: coeff %d differs (%d vs %d)", i, p1[i], p2[i])
		}
		if p1[i] >= polyQ {
			t.Fatalf("coeff %d = %d exceeds q=%d (rejection sampling broken)",
				i, p1[i], polyQ)
		}
	}
}

// TestRejSampleNonceSeparation confirms swapping i and j (i.e.
// changing the nonce from (i<<8)|j to (j<<8)|i) yields a different
// polynomial — without this, the matrix would have repeated rows or
// transposed entries.
func TestRejSampleNonceSeparation(t *testing.T) {
	var rho [32]byte
	for i := range rho {
		rho[i] = 0xA5
	}
	var p1, p2 [polyN]uint32
	rejSampleNTTPoly(&p1, &rho, (1<<8)|2)
	rejSampleNTTPoly(&p2, &rho, (2<<8)|1)
	same := true
	for i := 0; i < polyN; i++ {
		if p1[i] != p2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("nonce (1<<8)|2 and (2<<8)|1 produced identical polynomials")
	}
}

// TestExpandSet_MLDSA65 exercises the headline path: take a real
// FIPS 204 compact key, expand it, confirm sizes, confirm the
// Compact field is the input verbatim (defensive copy aside).
func TestExpandSet_MLDSA65(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, mldsa65.SeedSize)
	pk, _, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	compact := pk.Bytes()
	if len(compact) != mldsa65.PublicKeySize {
		t.Fatalf("compact size: got %d, want %d", len(compact), mldsa65.PublicKeySize)
	}

	exp, err := ExpandSet(MLDSA65, compact)
	if err != nil {
		t.Fatalf("ExpandSet: %v", err)
	}
	if exp.Set != MLDSA65 {
		t.Errorf("Set: got %v want MLDSA65", exp.Set)
	}
	if !bytes.Equal(exp.Compact, compact) {
		t.Error("Compact field differs from input")
	}
	if len(exp.ExpandedA) != ExpandedASize65 {
		t.Errorf("ExpandedA size: got %d want %d", len(exp.ExpandedA), ExpandedASize65)
	}

	// Confirm the defensive copy: mutating compact must NOT mutate exp.Compact.
	saved := exp.Compact[0]
	compact[0] ^= 0xFF
	if exp.Compact[0] != saved {
		t.Error("ExpandSet did not copy compact (input mutation propagates)")
	}
}

// TestExpand_AutoParamDetection verifies that Expand (no explicit
// set) routes to the right parameter set based on input length.
func TestExpand_AutoParamDetection(t *testing.T) {
	cases := []struct {
		name string
		size int
		set  ParamSet
	}{
		{"mldsa44", mldsa44.PublicKeySize, MLDSA44},
		{"mldsa65", mldsa65.PublicKeySize, MLDSA65},
		{"mldsa87", mldsa87.PublicKeySize, MLDSA87},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compact := make([]byte, tc.size)
			for i := range compact[:32] {
				compact[i] = byte(i ^ int(tc.set))
			}
			exp, err := Expand(compact)
			if err != nil {
				t.Fatalf("Expand: %v", err)
			}
			if exp.Set != tc.set {
				t.Errorf("inferred set: got %v want %v", exp.Set, tc.set)
			}
		})
	}
}

// TestExpand_RoundTrip is the headline property: Expand(Compact(Expand(x)))
// agrees byte-for-byte with Expand(x). Compact() must drop ExpandedA
// (per spec), so we re-derive on the second pass and compare.
func TestExpand_RoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0xC3}, mldsa65.SeedSize)
	pk, _, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	exp1, err := Expand(pk.Bytes())
	if err != nil {
		t.Fatalf("Expand #1: %v", err)
	}
	compact := Compact(exp1)
	exp2, err := Expand(compact)
	if err != nil {
		t.Fatalf("Expand #2: %v", err)
	}

	if exp1.Set != exp2.Set {
		t.Errorf("Set differs across round-trip: %v vs %v", exp1.Set, exp2.Set)
	}
	if !bytes.Equal(exp1.Compact, exp2.Compact) {
		t.Error("Compact differs across round-trip")
	}
	if !bytes.Equal(exp1.ExpandedA, exp2.ExpandedA) {
		t.Error("ExpandedA differs across round-trip — derivation is not deterministic")
	}
}

// TestExpandedVerify_MatchesCompactVerify confirms a synthetic key
// + signature verifies equivalently under (a) the canonical FIPS 204
// path in mldsa65.Verify and (b) the expanded-form Verify here. The
// two MUST agree for every signature; disagreement means the
// expanded path has introduced an oracle.
func TestExpandedVerify_MatchesCompactVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{0x77}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := []byte("expanded vs compact verifier parity")
	ctx := []byte("LUX/test/expanded")
	sig, err := mldsa65.Sign(sk, msg, ctx, false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !mldsa65.Verify(pk, msg, ctx, sig) {
		t.Fatal("compact Verify rejected its own signature")
	}

	exp, err := Expand(pk.Bytes())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !Verify(exp, msg, ctx, sig) {
		t.Fatal("expanded Verify rejected a signature compact Verify accepts")
	}
}

// TestExpandedVerify_RejectsTamperedSig flips one byte of the
// signature and asserts both verifiers (compact + expanded) reject.
func TestExpandedVerify_RejectsTamperedSig(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := []byte("tampered sig must reject")
	ctx := []byte("LUX/test/expanded-tamper")
	sig, err := mldsa65.Sign(sk, msg, ctx, false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig[7] ^= 0x01

	if mldsa65.Verify(pk, msg, ctx, sig) {
		t.Fatal("compact Verify accepted tampered sig (test setup broken)")
	}
	exp, err := Expand(pk.Bytes())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if Verify(exp, msg, ctx, sig) {
		t.Fatal("expanded Verify accepted a tampered signature")
	}
}

// TestExpandedVerify_RejectsTamperedCache flips one byte of
// ExpandedA and asserts Verify rejects (the cache-integrity check
// must prevent an attacker-supplied A from biasing verification).
func TestExpandedVerify_RejectsTamperedCache(t *testing.T) {
	seed := bytes.Repeat([]byte{0x99}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := []byte("tampered cache must reject")
	ctx := []byte("LUX/test/expanded-cache-tamper")
	sig, err := mldsa65.Sign(sk, msg, ctx, false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	exp, err := Expand(pk.Bytes())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	// Sanity: legit expanded form accepts.
	if !Verify(exp, msg, ctx, sig) {
		t.Fatal("baseline expanded Verify rejected a legitimate signature")
	}
	// Flip one bit deep inside ExpandedA.
	exp.ExpandedA[5000] ^= 0x80
	if Verify(exp, msg, ctx, sig) {
		t.Fatal("expanded Verify accepted a key with tampered ExpandedA cache")
	}
}

// TestExpandedVerify_RejectsSizeMismatch asserts a Compact field
// with the wrong length is refused without crashing.
func TestExpandedVerify_RejectsSizeMismatch(t *testing.T) {
	exp := &PublicKey{
		Set:     MLDSA65,
		Compact: make([]byte, mldsa65.PublicKeySize-1),
	}
	if Verify(exp, []byte("x"), nil, make([]byte, mldsa65.SignatureSize)) {
		t.Fatal("Verify accepted a short Compact")
	}
}

// TestExpandSet_RejectsUnknownSet pins the error path.
func TestExpandSet_RejectsUnknownSet(t *testing.T) {
	if _, err := ExpandSet(ParamSet(99), make([]byte, 1000)); err == nil {
		t.Fatal("ExpandSet accepted unknown parameter set")
	}
}

// TestExpand_RejectsBadSize confirms a length that does not match
// any FIPS 204 parameter set is rejected by Expand.
func TestExpand_RejectsBadSize(t *testing.T) {
	if _, err := Expand(make([]byte, 100)); err == nil {
		t.Fatal("Expand accepted a 100-byte input (no parameter set has this size)")
	}
}

// TestCompactNilSafe asserts Compact(nil) returns nil, not panic.
func TestCompactNilSafe(t *testing.T) {
	if b := Compact(nil); b != nil {
		t.Errorf("Compact(nil) = %v, want nil", b)
	}
}

// TestVerifyNilSafe asserts Verify(nil, ...) returns false, not panic.
func TestVerifyNilSafe(t *testing.T) {
	if Verify(nil, []byte("x"), nil, []byte("y")) {
		t.Fatal("Verify(nil) returned true")
	}
}

// TestExpand_AllParamSets exercises expand+verify on all three
// parameter sets so a regression in any one is caught here.
func TestExpand_AllParamSets(t *testing.T) {
	t.Run("MLDSA44", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0x44}, mldsa44.SeedSize)
		pk, sk, err := mldsa44.NewKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("NewKeyFromSeed: %v", err)
		}
		sig, err := mldsa44.Sign(sk, []byte("m"), []byte("c"), false)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		exp, err := Expand(pk.Bytes())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if exp.Set != MLDSA44 {
			t.Errorf("Set: got %v want MLDSA44", exp.Set)
		}
		if !Verify(exp, []byte("m"), []byte("c"), sig) {
			t.Fatal("MLDSA44 expanded Verify failed")
		}
	})
	t.Run("MLDSA87", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0x87}, mldsa87.SeedSize)
		pk, sk, err := mldsa87.NewKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("NewKeyFromSeed: %v", err)
		}
		sig, err := mldsa87.Sign(sk, []byte("m"), []byte("c"), false)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		exp, err := Expand(pk.Bytes())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if exp.Set != MLDSA87 {
			t.Errorf("Set: got %v want MLDSA87", exp.Set)
		}
		if !Verify(exp, []byte("m"), []byte("c"), sig) {
			t.Fatal("MLDSA87 expanded Verify failed")
		}
	})
}

// BenchmarkVerifyCompact is the baseline: vanilla mldsa65.Verify on
// a fixed (pk, msg, sig). Compare against BenchmarkVerifyExpanded
// to read the overhead/savings of the expanded path.
func BenchmarkVerifyCompact(b *testing.B) {
	seed := bytes.Repeat([]byte{0xBB}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		b.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := bytes.Repeat([]byte{0x33}, 256)
	ctx := []byte("LUX/bench/mldsa65/compact")
	sig, err := mldsa65.Sign(sk, msg, ctx, false)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !mldsa65.Verify(pk, msg, ctx, sig) {
			b.Fatal("verify failed mid-bench")
		}
	}
}

// BenchmarkVerifyExpanded measures the expanded-form Verify which
// pays for the integrity re-derivation of A on each call. With
// CIRCL's internal API still hidden, the expanded path is strictly
// slower than the compact path for a single verification; the win
// shows up only when a downstream verifier consumes the pre-derived
// A directly. Until that's wired, the benchmark exists as a true
// floor on the throughput cost of the integrity check.
func BenchmarkVerifyExpanded(b *testing.B) {
	seed := bytes.Repeat([]byte{0xBB}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		b.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := bytes.Repeat([]byte{0x33}, 256)
	ctx := []byte("LUX/bench/mldsa65/expanded")
	sig, err := mldsa65.Sign(sk, msg, ctx, false)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	exp, err := Expand(pk.Bytes())
	if err != nil {
		b.Fatalf("Expand: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(exp, msg, ctx, sig) {
			b.Fatal("verify failed mid-bench")
		}
	}
}

// BenchmarkExpand measures the one-time cost of building an
// expanded form from a compact key. This is the cost amortized
// across many verifications when the expanded form is cached.
func BenchmarkExpand(b *testing.B) {
	seed := bytes.Repeat([]byte{0xBB}, mldsa65.SeedSize)
	pk, _, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		b.Fatalf("NewKeyFromSeed: %v", err)
	}
	compact := pk.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Expand(compact); err != nil {
			b.Fatalf("Expand: %v", err)
		}
	}
}
