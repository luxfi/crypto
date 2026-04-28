// Copyright (C) 2026 Lux Industries Inc. All rights reserved.
// Licensed under Apache-2.0 OR MIT.
//
// Tests for the scalar-blinding wrapper around banderwagon.MultiExp.
// Two properties are checked:
//
//  1. Correctness: MultiExpBlinded(points, scalars) must produce the same
//     group element as MultiExp(points, scalars) on identical inputs. This
//     is a hard equality requirement — the blinding must cancel exactly.
//  2. Timing variance: across many invocations on the same scalar input,
//     the blinded path should exhibit non-trivial wall-clock variance
//     because a fresh r is drawn per call. This is an indication, not a
//     proof, that the trace observed by an attacker depends on r rather
//     than on the (constant) underlying scalars.

package ipa

import (
	"math"
	"testing"
	"time"

	"github.com/luxfi/crypto/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
	"github.com/luxfi/crypto/ipa/common"
)

// randomScalars returns n random Fr elements in Montgomery form (matching
// the convention used by every prover-side caller and the ScalarsMont: true
// flag passed to MultiExp).
func randomScalars(t *testing.T, n int) []fr.Element {
	t.Helper()
	s := make([]fr.Element, n)
	for i := range s {
		if _, err := s[i].SetRandom(); err != nil {
			t.Fatalf("SetRandom: %v", err)
		}
		// SetRandom returns a regular-form element; convert to Montgomery
		// form so subsequent arithmetic and MultiExp(ScalarsMont: true)
		// see consistent representation.
		s[i].ToMont()
	}
	return s
}

// TestMultiExpBlinded_Correctness verifies that the blinded MSM produces
// the same group element as the unblinded MSM across 100 random
// (points, scalars) pairs at multiple input lengths. This is the
// load-bearing property: the blinding must cancel exactly so that proofs
// produced through the blinded path verify under the unblinded verifier.
func TestMultiExpBlinded_Correctness(t *testing.T) {
	t.Parallel()

	// Use the SRS as a convenient source of group elements. The SRS is
	// public and 256 elements long, matching common.VectorLength.
	if ipaConf == nil {
		t.Fatal("ipaConf not initialized; TestMain should have set it")
	}
	srs := ipaConf.SRS

	// Sweep a few input sizes, including the 2-element shape used by the
	// four prover-side commitBlinded calls and the full vector length used
	// by IPAConfig.Commit.
	sizes := []int{2, 4, 8, 64, 128, int(common.VectorLength)}

	totalChecks := 0
	for _, sz := range sizes {
		points := srs[:sz]
		// 100 random scalar vectors per size.
		for trial := 0; trial < 100; trial++ {
			scalars := randomScalars(t, sz)

			var unblinded banderwagon.Element
			unblinded.SetIdentity()
			if _, err := unblinded.MultiExp(points, scalars, banderwagon.MultiExpConfig{ScalarsMont: true}); err != nil {
				t.Fatalf("size=%d trial=%d MultiExp: %v", sz, trial, err)
			}

			var blinded banderwagon.Element
			blinded.SetIdentity()
			if _, err := blinded.MultiExpBlinded(points, scalars, banderwagon.MultiExpConfig{ScalarsMont: true}); err != nil {
				t.Fatalf("size=%d trial=%d MultiExpBlinded: %v", sz, trial, err)
			}

			if !blinded.Equal(&unblinded) {
				t.Fatalf("size=%d trial=%d: blinded result != unblinded result", sz, trial)
			}
			totalChecks++
		}
	}
	t.Logf("verified %d blinded-vs-unblinded equality checks across %d input sizes", totalChecks, len(sizes))
}

// TestMultiExpBlinded_DoesNotMutateInputs ensures the helper never modifies
// the caller's scalar slice. The IPA prover passes witness halves directly,
// so silent mutation would corrupt the proof transcript.
func TestMultiExpBlinded_DoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	const n = 64
	points := ipaConf.SRS[:n]
	scalars := randomScalars(t, n)

	// Snapshot.
	snapshot := make([]fr.Element, n)
	copy(snapshot, scalars)

	var p banderwagon.Element
	p.SetIdentity()
	if _, err := p.MultiExpBlinded(points, scalars, banderwagon.MultiExpConfig{ScalarsMont: true}); err != nil {
		t.Fatalf("MultiExpBlinded: %v", err)
	}

	for i := range scalars {
		if !scalars[i].Equal(&snapshot[i]) {
			t.Fatalf("scalar[%d] mutated by MultiExpBlinded", i)
		}
	}
}

// TestMultiExpBlinded_LengthMismatch checks the explicit length-equality
// guard so that a wiring bug at a call site fails loudly instead of being
// papered over by the underlying MSM panicking.
func TestMultiExpBlinded_LengthMismatch(t *testing.T) {
	t.Parallel()

	points := ipaConf.SRS[:4]
	scalars := randomScalars(t, 5)

	var p banderwagon.Element
	p.SetIdentity()
	_, err := p.MultiExpBlinded(points, scalars, banderwagon.MultiExpConfig{ScalarsMont: true})
	if err == nil {
		t.Fatal("expected length-mismatch error, got nil")
	}
}

// TestMultiExpBlinded_TimingVariance is an indication-not-proof that
// MultiExpBlinded introduces per-call variance. We time 1000 iterations on a
// fixed scalar input and assert the standard deviation exceeds a small
// threshold (0.1% of the mean). Pippenger on identical inputs is highly
// repeatable, so without blinding the variance would collapse to noise from
// scheduling alone. A meaningful std-dev indicates the trace differs per
// call due to the fresh r.
//
// This is not a side-channel proof. It is a smoke test that the masking
// path is actually being exercised. Real evaluation must use a hardware
// cache-timing rig.
func TestMultiExpBlinded_TimingVariance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing variance test in -short mode")
	}
	t.Parallel()

	const n = 32
	const iterations = 1000

	points := ipaConf.SRS[:n]
	scalars := randomScalars(t, n)

	// Warm-up to amortize first-touch costs.
	for i := 0; i < 20; i++ {
		var p banderwagon.Element
		p.SetIdentity()
		if _, err := p.MultiExpBlinded(points, scalars, banderwagon.MultiExpConfig{ScalarsMont: true}); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}

	samples := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		var p banderwagon.Element
		p.SetIdentity()
		start := time.Now()
		if _, err := p.MultiExpBlinded(points, scalars, banderwagon.MultiExpConfig{ScalarsMont: true}); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		samples[i] = float64(time.Since(start).Nanoseconds())
	}

	mean := 0.0
	for _, s := range samples {
		mean += s
	}
	mean /= float64(iterations)

	variance := 0.0
	for _, s := range samples {
		d := s - mean
		variance += d * d
	}
	variance /= float64(iterations)
	std := math.Sqrt(variance)

	t.Logf("MultiExpBlinded over %d iters: mean=%.0fns std=%.0fns (cv=%.2f%%)", iterations, mean, std, 100*std/mean)

	// We expect a non-trivial std-dev. If std is tiny relative to the mean
	// either the blinding is being optimized away or the timing rig is
	// unable to resolve it — either way, flag it. Threshold deliberately
	// loose; this is an indication, not a constant-time proof.
	if std < mean*0.001 {
		t.Fatalf("std-dev %.0fns is suspiciously small relative to mean %.0fns; blinding may not be exercised", std, mean)
	}
}
