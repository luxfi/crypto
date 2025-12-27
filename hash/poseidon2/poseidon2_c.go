// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && darwin

// Package poseidon2 provides GPU-accelerated Poseidon2 hash functions via luxcpp/crypto.
// Poseidon2 is a ZK-friendly hash function designed for BN254 scalar field.
package poseidon2

/*
#cgo CFLAGS: -I/Users/z/work/luxcpp/crypto/include
#cgo darwin LDFLAGS: -L/Users/z/work/luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation
#cgo linux LDFLAGS: -L/Users/z/work/luxcpp/crypto/build-local -lluxcrypto

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_poseidon2.h"

*/
import "C"

import (
	"errors"
	"unsafe"
)

// ElementSize is the size of a BN254 scalar field element in bytes (256-bit).
const ElementSize = 32

// Element represents a 256-bit BN254 scalar field element.
// Stored as 4 x 64-bit limbs in little-endian order.
type Element [ElementSize]byte

// Threshold for GPU batch operations
const GPUThreshold = 64

// context is the global Metal Poseidon2 context (initialized on first use).
var (
	ctx      *C.MetalPoseidon2Context
	ctxReady bool
)

// initContext lazily initializes the Metal Poseidon2 context.
func initContext() error {
	if ctxReady {
		return nil
	}
	ctx = C.metal_poseidon2_init()
	if ctx == nil {
		return errors.New("Metal Poseidon2 initialization failed")
	}
	ctxReady = true
	return nil
}

// GPUAvailable returns true if Metal GPU acceleration is available.
func GPUAvailable() bool {
	return bool(C.metal_poseidon2_available())
}

// Threshold returns the recommended batch size for GPU offload.
func Threshold() uint32 {
	return GPUThreshold
}

// elementToFe256 converts Element to Poseidon2Fe256
func elementToFe256(e *Element) *C.Poseidon2Fe256 {
	return (*C.Poseidon2Fe256)(unsafe.Pointer(e))
}

// HashPair computes Poseidon2 hash of two elements (2-to-1 compression).
// This is the core operation for Merkle tree construction.
func HashPair(left, right Element) (Element, error) {
	var out Element
	if err := initContext(); err != nil {
		return out, err
	}

	ret := C.metal_poseidon2_compress(
		ctx,
		C.POSEIDON2_BN254,
		unsafe.Pointer(&out[0]),
		unsafe.Pointer(&left[0]),
		unsafe.Pointer(&right[0]),
	)
	if ret != C.METAL_POSEIDON2_SUCCESS {
		return out, errors.New("Poseidon2 hash pair failed")
	}
	return out, nil
}

// BatchHashPair computes Poseidon2 hashes for multiple pairs on GPU.
// More efficient than calling HashPair repeatedly for batch operations.
func BatchHashPair(left, right []Element) ([]Element, error) {
	n := len(left)
	if n == 0 || n != len(right) {
		return nil, errors.New("invalid input lengths")
	}
	if err := initContext(); err != nil {
		return nil, err
	}

	outputs := make([]Element, n)

	// Below threshold, process sequentially
	if uint32(n) < Threshold() || !GPUAvailable() {
		for i := 0; i < n; i++ {
			out, err := HashPair(left[i], right[i])
			if err != nil {
				return nil, err
			}
			outputs[i] = out
		}
		return outputs, nil
	}

	// GPU batch processing
	ret := C.metal_poseidon2_batch_compress(
		ctx,
		C.POSEIDON2_BN254,
		unsafe.Pointer(&outputs[0]),
		unsafe.Pointer(&left[0]),
		unsafe.Pointer(&right[0]),
		C.uint32_t(n),
	)
	if ret != C.METAL_POSEIDON2_SUCCESS {
		return nil, errors.New("Poseidon2 batch hash pair failed")
	}
	return outputs, nil
}

// MerkleLayer computes one layer of a Merkle tree from leaf pairs.
// Input size must be even. Output size is input size / 2.
func MerkleLayer(current []Element) ([]Element, error) {
	n := len(current)
	if n == 0 || n%2 != 0 {
		return nil, errors.New("layer size must be even")
	}
	if err := initContext(); err != nil {
		return nil, err
	}

	// Split into left and right halves for batch compress
	numPairs := n / 2
	lefts := make([]Element, numPairs)
	rights := make([]Element, numPairs)
	for i := 0; i < numPairs; i++ {
		lefts[i] = current[i*2]
		rights[i] = current[i*2+1]
	}

	return BatchHashPair(lefts, rights)
}

// MerkleTree builds a complete Merkle tree from leaves using GPU.
// Returns all internal nodes (num_leaves - 1 elements) with root at index 0.
// Number of leaves must be a power of 2.
func MerkleTree(leaves []Element) ([]Element, error) {
	n := len(leaves)
	if n == 0 || (n&(n-1)) != 0 {
		return nil, errors.New("leaves count must be a power of 2")
	}
	if err := initContext(); err != nil {
		return nil, err
	}

	// Tree has n-1 internal nodes
	tree := make([]Element, n-1)

	ret := C.metal_poseidon2_merkle_tree(
		ctx,
		C.POSEIDON2_BN254,
		unsafe.Pointer(&tree[0]),
		unsafe.Pointer(&leaves[0]),
		C.uint32_t(n),
	)
	if ret != C.METAL_POSEIDON2_SUCCESS {
		return nil, errors.New("Poseidon2 Merkle tree failed")
	}
	return tree, nil
}

// MerkleRoot computes just the Merkle root from leaves.
func MerkleRoot(leaves []Element) (Element, error) {
	var root Element
	if err := initContext(); err != nil {
		return root, err
	}

	ret := C.metal_poseidon2_merkle_root(
		ctx,
		C.POSEIDON2_BN254,
		unsafe.Pointer(&root[0]),
		unsafe.Pointer(&leaves[0]),
		C.uint32_t(len(leaves)),
	)
	if ret != C.METAL_POSEIDON2_SUCCESS {
		return root, errors.New("Poseidon2 Merkle root failed")
	}
	return root, nil
}

// VerifyProof verifies a single Merkle proof.
// Returns true if the proof is valid.
func VerifyProof(leaf, root Element, path []Element, indices []uint32) (bool, error) {
	if len(path) != len(indices) {
		return false, errors.New("path length mismatch")
	}
	if err := initContext(); err != nil {
		return false, err
	}

	depth := len(path)
	if depth == 0 {
		// Single node tree
		return leaf == root, nil
	}

	ret := C.metal_poseidon2_merkle_verify(
		ctx,
		C.POSEIDON2_BN254,
		unsafe.Pointer(&root[0]),
		unsafe.Pointer(&leaf[0]),
		unsafe.Pointer(&path[0]),
		C.uint32_t(indices[0]), // leaf index (first element represents full path)
		C.uint32_t(depth),
	)

	return ret == C.METAL_POSEIDON2_SUCCESS, nil
}

// BatchVerifyProofs verifies multiple Merkle proofs in parallel on GPU.
// Note: This implementation falls back to sequential verification as
// the metal_poseidon2 API doesn't have a batch verify function.
func BatchVerifyProofs(leaves, roots []Element, paths [][]Element, indices [][]uint32) ([]bool, error) {
	n := len(leaves)
	if n == 0 || n != len(roots) || n != len(paths) || n != len(indices) {
		return nil, errors.New("invalid input lengths")
	}

	results := make([]bool, n)
	for i := 0; i < n; i++ {
		valid, err := VerifyProof(leaves[i], roots[i], paths[i], indices[i])
		if err != nil {
			return nil, err
		}
		results[i] = valid
	}
	return results, nil
}

// Commitment computes a Pedersen-style commitment using Poseidon2.
// commitment = Poseidon2(value, blinding, salt)
func Commitment(value, blinding, salt Element) (Element, error) {
	// First hash value and blinding
	temp, err := HashPair(value, blinding)
	if err != nil {
		return Element{}, err
	}
	// Then hash result with salt
	return HashPair(temp, salt)
}

// BatchCommitment computes multiple commitments in parallel on GPU.
func BatchCommitment(values, blindings, salts []Element) ([]Element, error) {
	n := len(values)
	if n == 0 || n != len(blindings) || n != len(salts) {
		return nil, errors.New("invalid input lengths")
	}

	// First hash values and blindings
	temps, err := BatchHashPair(values, blindings)
	if err != nil {
		return nil, err
	}
	// Then hash results with salts
	return BatchHashPair(temps, salts)
}

// Nullifier computes a nullifier for spending a note.
// nullifier = Poseidon2(key, commitment, index)
func Nullifier(key, commitment, index Element) (Element, error) {
	// First hash key and commitment
	temp, err := HashPair(key, commitment)
	if err != nil {
		return Element{}, err
	}
	// Then hash result with index
	return HashPair(temp, index)
}

// BatchNullifier computes multiple nullifiers in parallel on GPU.
func BatchNullifier(keys, commitments, indices []Element) ([]Element, error) {
	n := len(keys)
	if n == 0 || n != len(commitments) || n != len(indices) {
		return nil, errors.New("invalid input lengths")
	}

	// First hash keys and commitments
	temps, err := BatchHashPair(keys, commitments)
	if err != nil {
		return nil, err
	}
	// Then hash results with indices
	return BatchHashPair(temps, indices)
}

// Destroy releases the Metal Poseidon2 context.
// Should be called when done with GPU operations.
func Destroy() {
	if ctxReady && ctx != nil {
		C.metal_poseidon2_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}

// Hash computes Poseidon2 hash of multiple elements (1-16) using Merkle-Damgard construction.
// This mirrors the gnark-crypto Poseidon2 Merkle-Damgard hasher behavior.
// For 2 elements, it uses HashPair directly. For more, it chains hashes.
func Hash(elements []Element) (Element, error) {
	n := len(elements)
	if n == 0 {
		return Element{}, errors.New("empty input")
	}
	if n > 16 {
		return Element{}, errors.New("too many elements: maximum 16")
	}

	// Single element: hash with zero element
	if n == 1 {
		return HashPair(elements[0], Element{})
	}

	// Two elements: direct hash pair
	if n == 2 {
		return HashPair(elements[0], elements[1])
	}

	// More elements: Merkle-Damgard construction
	// H(e0, e1) -> state
	// H(state, e2) -> state
	// ... continue until all elements consumed
	state, err := HashPair(elements[0], elements[1])
	if err != nil {
		return Element{}, err
	}

	for i := 2; i < n; i++ {
		state, err = HashPair(state, elements[i])
		if err != nil {
			return Element{}, err
		}
	}

	return state, nil
}

// HashFromBytes computes Poseidon2 hash from raw bytes.
// Input must be a multiple of 32 bytes (1-16 field elements).
// This is the main entry point for precompile use.
func HashFromBytes(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input)%ElementSize != 0 {
		return nil, errors.New("invalid input length: must be multiple of 32 bytes")
	}

	numElements := len(input) / ElementSize
	if numElements > 16 {
		return nil, errors.New("too many inputs: maximum 16 field elements")
	}

	// Parse into Elements
	elements := make([]Element, numElements)
	for i := 0; i < numElements; i++ {
		copy(elements[i][:], input[i*ElementSize:(i+1)*ElementSize])
	}

	result, err := Hash(elements)
	if err != nil {
		return nil, err
	}

	return result[:], nil
}
