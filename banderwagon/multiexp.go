// Copyright (C) 2026 Lux Industries Inc. All rights reserved.
// Copyright (C) Crate Crypto contributors.
// Licensed under Apache-2.0 OR MIT (see LICENSE-GO-IPA-APACHE2, LICENSE-GO-IPA-MIT).
//
// Provenance: ported from github.com/crate-crypto/go-ipa/banderwagon.

package banderwagon

import (
	"fmt"
	"math/big"

	"github.com/luxfi/crypto/ipa/bandersnatch"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
)

// MultiExpConfig enables to set optional configuration attribute to a call to MultiExp
type MultiExpConfig struct {
	NbTasks     int  // go routines to be used in the multiexp. can be larger than num cpus.
	ScalarsMont bool // indicates if the scalars are in montgomery form. Default to false.
}

// MultiExp calculates the multi exponentiation of points and scalars.
func (p *Element) MultiExp(points []Element, scalars []fr.Element, config MultiExpConfig) (*Element, error) {
	var projPoints = make([]bandersnatch.PointProj, len(points))
	for i := range points {
		projPoints[i] = points[i].inner
	}
	affinePoints := batchProjToAffine(projPoints)

	// NOTE: This is fine as long MultiExp does not use Equal functionality
	_, err := bandersnatch.MultiExp(&p.inner, affinePoints, scalars, bandersnatch.MultiExpConfig{
		NbTasks:     config.NbTasks,
		ScalarsMont: config.ScalarsMont,
	})

	return p, err
}

// qMinusTwo is q-2 where q is the Bandersnatch scalar-field modulus, used for
// Fermat-based inversion (a^(q-2) ≡ a^-1 mod q for a ≠ 0). Computing the
// inverse via Exp gives a constant-iteration ladder that does not branch on
// the secret scalar, in contrast to the variable-time extended-Euclidean
// algorithm used by fr.Element.Inverse.
var qMinusTwo = func() *big.Int {
	q := fr.Modulus()
	return new(big.Int).Sub(q, big.NewInt(2))
}()

// MultiExpBlinded computes the multi-exponentiation of points and scalars
// while masking the scalars from cache-timing side channels. Pippenger's
// window method (used by MultiExp) branches on scalar digits, so an attacker
// observing the cache trace can recover information about secret scalars
// passed by the prover (witness halves, blinding factors, opening points).
//
// To frustrate this attack we apply multiplicative randomization:
//
//  1. Sample a fresh random r ∈ Fr* per call (re-rolling on r=0).
//  2. Run MultiExp on (k_i · r) instead of k_i. The result is r · Σ k_i·P_i.
//  3. Multiply the result by r⁻¹ to recover Σ k_i·P_i.
//
// The trace observed by an attacker depends on (k_i · r) where r is fresh
// per call, so traces from repeated calls do not accumulate information
// about the underlying secret scalars k_i. r⁻¹ is computed via Fermat
// (r^(q-2)) so the inversion itself is also independent of secret data.
//
// The returned Element is identical to what MultiExp would produce on the
// same inputs (verified by the test suite); only the side-channel profile
// changes.
func (p *Element) MultiExpBlinded(points []Element, scalars []fr.Element, config MultiExpConfig) (*Element, error) {
	if len(points) != len(scalars) {
		return nil, fmt.Errorf("points and scalars must have equal length, %d != %d", len(points), len(scalars))
	}

	// Sample r ∈ Fr* using crypto/rand (fr.Element.SetRandom calls
	// crypto/rand internally). SetRandom returns a *regular-form* element;
	// the rest of the field-arithmetic API (Mul, Exp) assumes Montgomery
	// form, so we explicitly convert. Re-roll on the negligible chance
	// r = 0.
	var r fr.Element
	for {
		if _, err := r.SetRandom(); err != nil {
			return nil, fmt.Errorf("sampling blinding scalar: %w", err)
		}
		if !r.IsZero() {
			break
		}
	}
	r.ToMont()

	// Build (k_i · r) without mutating the caller's scalar slice. Both
	// scalars[i] and r are in Montgomery form so the product is also
	// Montgomery, matching the ScalarsMont: true expectation downstream.
	blinded := make([]fr.Element, len(scalars))
	for i := range scalars {
		blinded[i].Mul(&scalars[i], &r)
	}

	// Run the underlying (variable-time) MSM on the blinded scalars.
	if _, err := p.MultiExp(points, blinded, config); err != nil {
		return nil, err
	}

	// r⁻¹ = r^(q-2) mod q via Fermat's little theorem. Exp uses
	// Square/Mul which both operate in Montgomery form, so feeding it
	// Montgomery r yields Montgomery r⁻¹. Constant-iteration ladder, no
	// branching on secret bits.
	var rInv fr.Element
	rInv.Exp(r, qMinusTwo)

	// Recover the unblinded result: P = (r · P) · r⁻¹. ScalarMul on
	// banderwagon.Element expects a Montgomery-form scalar.
	p.ScalarMul(p, &rInv)

	// gnark's scalarMulGLV produces a non-canonical projective form for
	// the identity element (Y=0 instead of Y=1) which trips the early
	// IsZero-and-IsZero short-circuit in Element.Equal. The MSM result
	// being identity is observable from the compressed bytes (which are
	// derived only from public IPA structure such as all-zero witness
	// halves), so this normalization is not a side channel on r. Restore
	// the canonical identity representation when needed.
	if p.Bytes() == Identity.Bytes() {
		*p = Identity
	}

	return p, nil
}
