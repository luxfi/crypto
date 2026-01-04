// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// Package gpu provides GPU-accelerated Poseidon2 hash functions.
// This is the stub implementation when GPU acceleration is not available.
package gpu

import (
	"errors"
)

// ErrNotAvailable is returned when GPU acceleration is not available.
var ErrNotAvailable = errors.New("GPU acceleration not available")

// ElementSize is the size of a BN254 scalar field element in bytes (256-bit).
const ElementSize = 32

// Element represents a 256-bit BN254 scalar field element.
type Element [ElementSize]byte

// Available returns true if Metal GPU acceleration is available.
func Available() bool {
	return false
}

// Threshold returns the recommended batch size for GPU offload.
func Threshold() uint32 {
	return 0
}

// HashPair computes Poseidon2 hash of two elements (2-to-1 compression).
func HashPair(left, right Element) (Element, error) {
	return Element{}, ErrNotAvailable
}

// Hash computes Poseidon2 hash of variable-length input.
func Hash(input []Element) (Element, error) {
	return Element{}, ErrNotAvailable
}

// BatchHashPair computes multiple 2-to-1 compressions in parallel.
func BatchHashPair(pairs [][2]Element) ([]Element, error) {
	return nil, ErrNotAvailable
}

// MerkleRoot computes the Merkle tree root from leaves.
func MerkleRoot(leaves []Element) (Element, error) {
	return Element{}, ErrNotAvailable
}

// MerklePath computes the Merkle proof path for a leaf.
func MerklePath(leaves []Element, index uint32) ([]Element, error) {
	return nil, ErrNotAvailable
}
