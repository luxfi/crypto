// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package merkle is the canonical native-Go implementation of the keccak256
// tagged binary Merkle state-root fold. It is the authority that the Lux GPU
// state-root accelerators (CUDA, HIP, Metal, Vulkan, WGSL) must reproduce
// byte-for-byte.
//
// The construction follows RFC 6962 (Certificate Transparency):
//
//	leaf_hash(d)     = keccak256(0x00 ‖ d)        // d is a 32-byte element digest
//	node_hash(L, R)  = keccak256(0x01 ‖ L ‖ R)    // L, R are 32-byte child digests
//	empty root       = keccak256("")              // c5d2…a470
//
// The tree is bottom-up binary with RFC 6962 lone-right promotion: on an odd
// level the last node is promoted UNCHANGED (never hashed with itself, never
// duplicated — this avoids the CVE-2012-2459 root-malleability of Bitcoin's
// duplicate-last rule). Each level reduces cnt → ceil(cnt/2). The tree shape
// depends only on the leaf count, never on digest values, so it is reproducible
// bit-for-bit across every backend.
//
// The 0x00/0x01 tags domain-separate leaf and node inputs, closing the
// second-preimage ambiguity an untagged tree carries: a leaf input always
// starts 0x00, a node input always starts 0x01, and the empty root is the hash
// of the zero-length string — three disjoint input domains.
//
// The normative specification (and the C++ CPU reference these bytes match) is
// lux-private/gpu-kernels/backends/common/lux_merkle_fold.hpp.
package merkle

import "github.com/luxfi/crypto/hash"

// Size is the byte length of a Merkle digest (a keccak256 output).
const Size = hash.KeccakSize

const (
	leafTag byte = 0x00 // leaf_hash(d)    = keccak256(0x00 ‖ d)
	nodeTag byte = 0x01 // node_hash(L, R) = keccak256(0x01 ‖ L ‖ R)
)

// LeafHash returns keccak256(0x00 ‖ d), the tagged hash of a 32-byte element
// digest at the leaf level.
func LeafHash(d [Size]byte) [Size]byte {
	return hash.ComputeKeccak256Array([]byte{leafTag}, d[:])
}

// NodeHash returns keccak256(0x01 ‖ left ‖ right), the tagged hash of an
// internal node over its two 32-byte children.
func NodeHash(left, right [Size]byte) [Size]byte {
	return hash.ComputeKeccak256Array([]byte{nodeTag}, left[:], right[:])
}

// EmptyRoot returns keccak256(""), the root of the empty leaf set.
func EmptyRoot() [Size]byte {
	return hash.ComputeKeccak256Array()
}

// Root computes the keccak256 tagged binary Merkle root over leaves, which is a
// dense slice of 32-byte element digests already compacted to the occupied set
// in ascending order.
//
//	len == 0  → keccak256("")        (EmptyRoot)
//	len == 1  → LeafHash(leaves[0])  (single leaf, no internal node)
//	len  > 1  → bottom-up tagged binary tree with RFC 6962 lone-right promotion
//
// leaves is not modified.
func Root(leaves [][Size]byte) [Size]byte {
	n := len(leaves)
	if n == 0 {
		return EmptyRoot()
	}

	// Level 0: tag every leaf digest.
	level := make([][Size]byte, n)
	for i := range leaves {
		level[i] = LeafHash(leaves[i])
	}

	// Reduce level-by-level until one node remains.
	for len(level) > 1 {
		cnt := len(level)
		parents := (cnt + 1) / 2 // ceil(cnt/2)
		next := make([][Size]byte, parents)
		pairs := cnt / 2 // floor(cnt/2)
		for j := 0; j < pairs; j++ {
			next[j] = NodeHash(level[2*j], level[2*j+1])
		}
		if cnt&1 == 1 {
			// Lone right node: promote unchanged.
			next[parents-1] = level[cnt-1]
		}
		level = next
	}

	return level[0]
}
