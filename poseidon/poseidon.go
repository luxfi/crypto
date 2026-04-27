// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// FieldSize is the size of a BN254 scalar field element in bytes.
const FieldSize = 32

var ErrInvalidFieldSize = errors.New("poseidon: input must be a multiple of 32 bytes")

// Sum2 computes the Poseidon2 hash of `inputs` interpreted as a sequence of
// 32-byte BN254 scalar field elements. It returns a single 32-byte digest.
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
