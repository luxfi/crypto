// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"crypto/rand"
	"crypto/sha256"
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
// crypto/rand. A 32-byte random seed is drawn from rng and passed through
// NewGeneratorsFromSeed, so production callers and KAT generators traverse the
// same canonical derivation (single SeededGenDST + counter index 0/1) — no
// brand-specific or per-generator DST.
func NewGenerators(rng io.Reader) (*Generators, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var seed [32]byte
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return nil, err
	}
	return NewGeneratorsFromSeed(seed)
}

// DeterministicGenerators returns generators derived from a published seed of
// arbitrary length. Two callers passing the same seed get the same (G, H).
// Used for KAT vectors that must be reproducible across implementations and
// machines.
//
// The arbitrary-length input is compressed to a fixed 32-byte key with
// SHA-256 and then dispatched to NewGeneratorsFromSeed, so the actual on-curve
// derivation is identical to the C++/Metal/CUDA/WGSL canonical:
//
//	key = SHA-256(seed)
//	G   = HashToG1(key || u64_le(0), DST=PEDERSEN_SEEDED_GEN_V1)
//	H   = HashToG1(key || u64_le(1), DST=PEDERSEN_SEEDED_GEN_V1)
//
// This collapses LP-137 issue N3 (RED-FINAL §2.4): the legacy two-DST
// PEDERSEN_G_V1 / PEDERSEN_H_V1 path is removed; everything now flows through
// the single PEDERSEN_SEEDED_GEN_V1 DST that the C++ canonical uses.
func DeterministicGenerators(seed []byte) (*Generators, error) {
	key := sha256.Sum256(seed)
	return NewGeneratorsFromSeed(key)
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
