// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// SeededGenDST is the domain separation tag used by NewGeneratorsFromSeed.
// It is exported so cross-language KAT generators (C++, Rust) can replicate
// the derivation byte-for-byte.
const SeededGenDST = "PEDERSEN_SEEDED_GEN_V1"

// NewGeneratorsFromSeed deterministically derives the Pedersen generators
// (G, H) from a 32-byte seed using RFC 9380 hash-to-curve (SVDW map) on
// BN254 G1.
//
// Derivation algorithm (replicate exactly in C++/Rust for KAT parity):
//
//  1. msg_i = seed (32 bytes) || u64_le(i)   for i in {0, 1}
//  2. P_i   = bn254.HashToG1(msg_i, dst=SeededGenDST)
//  3. G = P_0,  H = P_1
//
// where u64_le(i) is the 8-byte little-endian encoding of i. Because BN254
// G1 has cofactor 1, every output of HashToG1 is in the prime-order subgroup,
// so no clearing is needed.
//
// Same seed → identical (G, H) on every machine, every run.
//
// Use this constructor for cross-language Known-Answer-Test (KAT) generation
// or for any setting that requires reproducibility. For production where a
// fresh, non-reproducible basis is desired, use NewGenerators(nil) instead.
func NewGeneratorsFromSeed(seed [32]byte) (*Generators, error) {
	g, err := hashIndexedG1(seed, 0)
	if err != nil {
		return nil, err
	}
	h, err := hashIndexedG1(seed, 1)
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

// hashIndexedG1 returns HashToG1(seed || u64_le(index), dst=SeededGenDST).
func hashIndexedG1(seed [32]byte, index uint64) (bn254.G1Affine, error) {
	var msg [40]byte
	copy(msg[:32], seed[:])
	// little-endian u64
	for i := uint64(0); i < 8; i++ {
		msg[32+i] = byte(index >> (8 * i))
	}
	return bn254.HashToG1(msg[:], []byte(SeededGenDST))
}
