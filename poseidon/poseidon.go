// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// FieldSize is the size of a BN254 scalar field element in bytes.
const FieldSize = 32

// Poseidon2 default parameters for BN254 scalar field, t=2 (compression mode).
// Matches gnark-crypto's GetDefaultParameters().
const (
	Width         = 2
	FullRounds    = 6
	PartialRounds = 50
	SBoxDegree    = 5
)

var ErrInvalidFieldSize = errors.New("poseidon: input must be a multiple of 32 bytes")

// Sum2 computes the Poseidon2 hash of `inputs` interpreted as a sequence of
// 32-byte BN254 scalar field elements via Merkle-Damgard. It returns a single
// 32-byte digest.
//
// inputs must have length divisible by 32. Empty input is permitted and
// returns the Poseidon2 hash of the empty preimage (well-defined per the
// gnark-crypto spec).
func Sum2(inputs []byte) ([FieldSize]byte, error) {
	var out [FieldSize]byte
	if len(inputs)%FieldSize != 0 {
		return out, ErrInvalidFieldSize
	}
	h := poseidon2.NewMerkleDamgardHasher()
	if _, err := h.Write(inputs); err != nil {
		return out, err
	}
	digest := h.Sum(nil)
	copy(out[:], digest)
	return out, nil
}

// Permutation2 applies the raw t=2 Poseidon2 permutation in-place to the
// given two field elements (each 32 bytes, big-endian, canonical reduced).
// This is the layer that the C++ and Metal implementations are byte-equal to.
//
// Both `left` and `right` are read and overwritten with the permutation
// output. They must each be exactly 32 bytes and below the BN254 scalar
// modulus.
func Permutation2(left, right *[FieldSize]byte) error {
	var s [Width]fr.Element
	if err := s[0].SetBytesCanonical(left[:]); err != nil {
		return err
	}
	if err := s[1].SetBytesCanonical(right[:]); err != nil {
		return err
	}
	p := poseidon2.NewPermutation(Width, FullRounds, PartialRounds)
	if err := p.Permutation(s[:]); err != nil {
		return err
	}
	copy(left[:], s[0].Marshal())
	copy(right[:], s[1].Marshal())
	return nil
}

// Compress2 absorbs (left, right) through the t=2 Poseidon2 permutation and
// returns the canonical 32-byte field element output (equivalent to
// gnark-crypto's Compress: returns state[1]+right_input after permutation).
func Compress2(left, right *[FieldSize]byte) ([FieldSize]byte, error) {
	var out [FieldSize]byte
	p := poseidon2.NewPermutation(Width, FullRounds, PartialRounds)
	res, err := p.Compress(left[:], right[:])
	if err != nil {
		return out, err
	}
	copy(out[:], res)
	return out, nil
}
