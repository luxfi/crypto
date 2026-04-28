// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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

// ErrIdenticalGenerators is returned when two derived generators collide.
var ErrIdenticalGenerators = errors.New("pedersen: G and H must be independent generators")

// ErrLength is returned when batch slices disagree on length.
var ErrLength = errors.New("pedersen: slice length mismatch")

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

// DeterministicGenerators returns generators derived from a published seed.
// Two callers passing the same seed get the same (G, H). Used for KAT
// vectors that must be reproducible across implementations and machines.
//
// Encoding: counter || seed -> SHA-256 -> hash-to-curve. Counter starts at 0
// for G; the first counter that produces a valid G1 point is taken; H uses
// the next counter that produces a *distinct* point.
func DeterministicGenerators(seed []byte) (*Generators, error) {
	deriveOne := func(counter uint32, dst []byte) (bn254.G1Affine, error) {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], counter)
		h := sha256.New()
		h.Write(buf[:])
		h.Write(seed)
		digest := h.Sum(nil)
		return bn254.HashToG1(digest, dst)
	}
	g, err := deriveOne(0, []byte("PEDERSEN_G_V1"))
	if err != nil {
		return nil, err
	}
	var h bn254.G1Affine
	for c := uint32(1); c < 1024; c++ {
		hp, err := deriveOne(c, []byte("PEDERSEN_H_V1"))
		if err != nil {
			return nil, err
		}
		if !hp.Equal(&g) {
			h = hp
			break
		}
	}
	if h.IsInfinity() {
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

// CommitBatch returns Commit(m[i], r[i]) for every i in lockstep. m and r
// must have the same length. The result preserves order. Used by callers
// that need to commit to many (m, r) pairs in one shot (block-STM commit
// stage, batched prover, GPU dispatch). Each commitment is independent;
// the batched form simply spares the caller a loop and gives the C++ /
// Metal layer a contiguous workload to dispatch on.
func (gens *Generators) CommitBatch(m, r []fr.Element) ([]Commitment, error) {
	if len(m) != len(r) {
		return nil, ErrLength
	}
	out := make([]Commitment, len(m))
	for i := range m {
		out[i] = gens.Commit(&m[i], &r[i])
	}
	return out, nil
}
