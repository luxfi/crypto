// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Commitment is a single point on BN254 G1.
type Commitment = bn254.G1Affine

// Generators holds the two independent generators G and H used for a single
// Pedersen commitment scheme instance. Reusing the same Generators across
// commitments is required for them to add and compare meaningfully.
type Generators struct {
	G bn254.G1Jac
	H bn254.G1Jac
}

var ErrIdenticalGenerators = errors.New("pedersen: G and H must be independent generators")

// NewGenerators samples two independent G1 generators. rng may be nil to use
// crypto/rand. The two generators are derived from independent hashes-to-curve
// of fresh randomness, ensuring no known relation between them.
func NewGenerators(rng io.Reader) (*Generators, error) {
	if rng == nil {
		rng = rand.Reader
	}
	gBytes := make([]byte, 64)
	if _, err := rng.Read(gBytes); err != nil {
		return nil, err
	}
	hBytes := make([]byte, 64)
	if _, err := rng.Read(hBytes); err != nil {
		return nil, err
	}
	g, err := bn254.HashToG1(gBytes, []byte("PEDERSEN_G_V1"))
	if err != nil {
		return nil, err
	}
	h, err := bn254.HashToG1(hBytes, []byte("PEDERSEN_H_V1"))
	if err != nil {
		return nil, err
	}
	if g.Equal(&h) {
		return nil, ErrIdenticalGenerators
	}
	gen := &Generators{}
	gen.G.FromAffine(&g)
	gen.H.FromAffine(&h)
	return gen, nil
}

// Commit returns Commit(m, r) = m*G + r*H.
func (gens *Generators) Commit(m, r *fr.Element) Commitment {
	var mScalar, rScalar fr.Element
	mScalar.Set(m)
	rScalar.Set(r)

	mBig := new(big.Int)
	rBig := new(big.Int)
	mScalar.BigInt(mBig)
	rScalar.BigInt(rBig)

	var mG, rH bn254.G1Jac
	mG.ScalarMultiplication(&gens.G, mBig)
	rH.ScalarMultiplication(&gens.H, rBig)

	var c bn254.G1Jac
	c.Set(&mG).AddAssign(&rH)
	var out Commitment
	out.FromJacobian(&c)
	return out
}
