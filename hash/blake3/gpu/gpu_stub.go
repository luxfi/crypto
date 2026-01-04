// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !luxgpu

// Package gpu provides GPU-accelerated Blake3 hash functions.
// This is the stub implementation when GPU acceleration is not available.
package gpu

import (
	"lukechampine.com/blake3"
)

const (
	// Size256 is the standard Blake3 output size
	Size256 = 32
	// Size512 is extended Blake3 output size
	Size512 = 64
	// BatchThreshold is minimum batch size for GPU acceleration
	BatchThreshold = 64
)

// Available returns true if GPU acceleration is available.
func Available() bool {
	return false
}

// Backend returns the active backend name.
func Backend() string {
	return "CPU"
}

// Sum256 computes a 32-byte Blake3 hash.
func Sum256(data []byte) [Size256]byte {
	return blake3.Sum256(data)
}

// Sum512 computes a 64-byte Blake3 hash.
func Sum512(data []byte) [Size512]byte {
	return blake3.Sum512(data)
}

// SumXOF computes an extendable output hash of arbitrary length.
func SumXOF(data []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	h := blake3.New(outLen, nil)
	h.Write(data)
	return h.Sum(nil)
}

// BatchSum256 computes multiple 32-byte hashes.
func BatchSum256(inputs [][]byte) [][Size256]byte {
	results := make([][Size256]byte, len(inputs))
	for i, input := range inputs {
		results[i] = blake3.Sum256(input)
	}
	return results
}

// MerkleRoot computes the Merkle root of leaves using Blake3.
func MerkleRoot(leaves [][]byte) [Size256]byte {
	if len(leaves) == 0 {
		return [Size256]byte{}
	}
	if len(leaves) == 1 {
		return blake3.Sum256(leaves[0])
	}
	// Simple iterative merkle tree
	hashes := make([][Size256]byte, len(leaves))
	for i, leaf := range leaves {
		hashes[i] = blake3.Sum256(leaf)
	}
	for len(hashes) > 1 {
		next := make([][Size256]byte, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i][:], hashes[i+1][:]...)
				next[i/2] = blake3.Sum256(combined)
			} else {
				next[i/2] = hashes[i]
			}
		}
		hashes = next
	}
	return hashes[0]
}

// DeriveKey derives a key using Blake3 KDF.
func DeriveKey(context, key []byte) [Size256]byte {
	h := blake3.New(Size256, key)
	h.Write(context)
	var out [Size256]byte
	copy(out[:], h.Sum(nil))
	return out
}
