// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build luxgpu && darwin

// Package gpu provides GPU-accelerated Poseidon2 hash functions via Metal.
// This package links to luxcpp/crypto for hardware acceleration.
// The C++ library handles automatic fallback to CPU when GPU is unavailable.
// Poseidon2 is a ZK-friendly hash function designed for BN254 scalar field.
package gpu

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../../luxcpp/crypto/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../../luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_zk.h"
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

// context is the global Metal ZK context (initialized on first use).
var (
	ctx      *C.MetalZKContext
	ctxReady bool
)

// initContext lazily initializes the Metal ZK context.
func initContext() error {
	if ctxReady {
		return nil
	}
	ctx = C.metal_zk_init()
	if ctx == nil {
		return errors.New("Metal ZK initialization failed")
	}
	ctxReady = true
	return nil
}

// Available returns true if Metal GPU acceleration is available.
func Available() bool {
	return bool(C.metal_zk_available())
}

// Threshold returns the recommended batch size for GPU offload.
func Threshold() uint32 {
	return uint32(C.metal_zk_get_threshold(C.METAL_ZK_OP_POSEIDON2_HASH))
}

// HashPair computes Poseidon2 hash of two elements (2-to-1 compression).
// This is the core operation for Merkle tree construction.
func HashPair(left, right Element) (Element, error) {
	var out Element
	if err := initContext(); err != nil {
		return out, err
	}

	leftFr := (*C.Fr256)(unsafe.Pointer(&left[0]))
	rightFr := (*C.Fr256)(unsafe.Pointer(&right[0]))
	outFr := (*C.Fr256)(unsafe.Pointer(&out[0]))

	ret := C.metal_zk_poseidon2_hash_pair(ctx, outFr, leftFr, rightFr, 1)
	if ret != C.METAL_ZK_SUCCESS {
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

	// GPU batch processing
	leftFr := (*C.Fr256)(unsafe.Pointer(&left[0]))
	rightFr := (*C.Fr256)(unsafe.Pointer(&right[0]))
	outFr := (*C.Fr256)(unsafe.Pointer(&outputs[0]))

	ret := C.metal_zk_poseidon2_hash_pair(ctx, outFr, leftFr, rightFr, C.uint32_t(n))
	if ret != C.METAL_ZK_SUCCESS {
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

	output := make([]Element, n/2)
	currentFr := (*C.Fr256)(unsafe.Pointer(&current[0]))
	outFr := (*C.Fr256)(unsafe.Pointer(&output[0]))

	ret := C.metal_zk_poseidon2_merkle_layer(ctx, outFr, currentFr, C.uint32_t(n))
	if ret != C.METAL_ZK_SUCCESS {
		return nil, errors.New("Poseidon2 Merkle layer failed")
	}
	return output, nil
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
	leavesFr := (*C.Fr256)(unsafe.Pointer(&leaves[0]))
	treeFr := (*C.Fr256)(unsafe.Pointer(&tree[0]))

	ret := C.metal_zk_poseidon2_merkle_tree(ctx, treeFr, leavesFr, C.uint32_t(n))
	if ret != C.METAL_ZK_SUCCESS {
		return nil, errors.New("Poseidon2 Merkle tree failed")
	}
	return tree, nil
}

// MerkleRoot computes just the Merkle root from leaves.
func MerkleRoot(leaves []Element) (Element, error) {
	var root Element
	tree, err := MerkleTree(leaves)
	if err != nil {
		return root, err
	}
	if len(tree) > 0 {
		root = tree[0]
	}
	return root, nil
}

// VerifyProof verifies a single Merkle proof.
// Returns true if the proof is valid.
func VerifyProof(leaf, root Element, path []Element, indices []uint32) (bool, error) {
	results, err := BatchVerifyProofs([]Element{leaf}, []Element{root}, [][]Element{path}, [][]uint32{indices})
	if err != nil {
		return false, err
	}
	return results[0], nil
}

// BatchVerifyProofs verifies multiple Merkle proofs in parallel on GPU.
func BatchVerifyProofs(leaves, roots []Element, paths [][]Element, indices [][]uint32) ([]bool, error) {
	n := len(leaves)
	if n == 0 || n != len(roots) || n != len(paths) || n != len(indices) {
		return nil, errors.New("invalid input lengths")
	}
	if n > 0 && len(paths[0]) != len(indices[0]) {
		return nil, errors.New("path length mismatch")
	}
	if err := initContext(); err != nil {
		return nil, err
	}

	pathLen := len(paths[0])
	results := make([]C.int, n)

	// Flatten paths and indices
	flatPaths := make([]Element, n*pathLen)
	flatIndices := make([]uint32, n*pathLen)
	for i := 0; i < n; i++ {
		copy(flatPaths[i*pathLen:], paths[i])
		copy(flatIndices[i*pathLen:], indices[i])
	}

	leavesFr := (*C.Fr256)(unsafe.Pointer(&leaves[0]))
	rootsFr := (*C.Fr256)(unsafe.Pointer(&roots[0]))
	pathsFr := (*C.Fr256)(unsafe.Pointer(&flatPaths[0]))
	indicesPtr := (*C.uint32_t)(unsafe.Pointer(&flatIndices[0]))
	resultsPtr := (*C.int)(unsafe.Pointer(&results[0]))

	ret := C.metal_zk_poseidon2_verify_proofs(
		ctx,
		resultsPtr,
		leavesFr,
		pathsFr,
		indicesPtr,
		rootsFr,
		C.uint32_t(n),
		C.uint32_t(pathLen),
	)
	if ret != C.METAL_ZK_SUCCESS {
		return nil, errors.New("Poseidon2 batch verify proofs failed")
	}

	boolResults := make([]bool, n)
	for i := 0; i < n; i++ {
		boolResults[i] = results[i] != 0
	}
	return boolResults, nil
}

// Commitment computes a Pedersen-style commitment using Poseidon2.
// commitment = Poseidon2(value, blinding, salt)
func Commitment(value, blinding, salt Element) (Element, error) {
	commitments, err := BatchCommitment([]Element{value}, []Element{blinding}, []Element{salt})
	if err != nil {
		return Element{}, err
	}
	return commitments[0], nil
}

// BatchCommitment computes multiple commitments in parallel on GPU.
func BatchCommitment(values, blindings, salts []Element) ([]Element, error) {
	n := len(values)
	if n == 0 || n != len(blindings) || n != len(salts) {
		return nil, errors.New("invalid input lengths")
	}
	if err := initContext(); err != nil {
		return nil, err
	}

	outputs := make([]Element, n)
	valuesFr := (*C.Fr256)(unsafe.Pointer(&values[0]))
	blindingsFr := (*C.Fr256)(unsafe.Pointer(&blindings[0]))
	saltsFr := (*C.Fr256)(unsafe.Pointer(&salts[0]))
	outFr := (*C.Fr256)(unsafe.Pointer(&outputs[0]))

	ret := C.metal_zk_batch_commitment(ctx, outFr, valuesFr, blindingsFr, saltsFr, C.uint32_t(n))
	if ret != C.METAL_ZK_SUCCESS {
		return nil, errors.New("Poseidon2 batch commitment failed")
	}
	return outputs, nil
}

// Nullifier computes a nullifier for spending a note.
// nullifier = Poseidon2(key, commitment, index)
func Nullifier(key, commitment, index Element) (Element, error) {
	nullifiers, err := BatchNullifier([]Element{key}, []Element{commitment}, []Element{index})
	if err != nil {
		return Element{}, err
	}
	return nullifiers[0], nil
}

// BatchNullifier computes multiple nullifiers in parallel on GPU.
func BatchNullifier(keys, commitments, indices []Element) ([]Element, error) {
	n := len(keys)
	if n == 0 || n != len(commitments) || n != len(indices) {
		return nil, errors.New("invalid input lengths")
	}
	if err := initContext(); err != nil {
		return nil, err
	}

	outputs := make([]Element, n)
	keysFr := (*C.Fr256)(unsafe.Pointer(&keys[0]))
	commitmentsFr := (*C.Fr256)(unsafe.Pointer(&commitments[0]))
	indicesFr := (*C.Fr256)(unsafe.Pointer(&indices[0]))
	outFr := (*C.Fr256)(unsafe.Pointer(&outputs[0]))

	ret := C.metal_zk_batch_nullifier(ctx, outFr, keysFr, commitmentsFr, indicesFr, C.uint32_t(n))
	if ret != C.METAL_ZK_SUCCESS {
		return nil, errors.New("Poseidon2 batch nullifier failed")
	}
	return outputs, nil
}

// Destroy releases the Metal ZK context.
// Should be called when done with GPU operations.
func Destroy() {
	if ctxReady && ctx != nil {
		C.metal_zk_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}
