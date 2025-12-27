// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !darwin || !luxcpp

// Package blake3 provides pure Go Blake3 hash functions.
// This is the fallback when the CGO-accelerated version is unavailable.
package blake3

import (
	"encoding/binary"
)

const (
	// Size256 is the standard Blake3 output size
	Size256 = 32
	// Size512 is extended Blake3 output size
	Size512 = 64
)

// GPUAvailable returns false for pure Go implementation.
func GPUAvailable() bool {
	return false
}

// Backend returns "Go" for pure Go implementation.
func Backend() string {
	return "Go"
}

// Sum256 computes a 32-byte Blake3 hash using zeebo/blake3.
func Sum256(data []byte) [Size256]byte {
	h := New()
	h.Write(data)
	var out [Size256]byte
	h.Reader().Read(out[:])
	return out
}

// Sum512 computes a 64-byte Blake3 hash using XOF mode.
func Sum512(data []byte) [Size512]byte {
	h := New()
	h.Write(data)
	var out [Size512]byte
	h.Reader().Read(out[:])
	return out
}

// SumXOF computes an extendable output hash of arbitrary length.
func SumXOF(data []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	h := New()
	h.Write(data)
	out := make([]byte, outLen)
	h.Reader().Read(out)
	return out
}

// BatchSum256 computes Blake3 hashes for multiple inputs.
// Pure Go version processes sequentially.
func BatchSum256(inputs [][]byte) [][Size256]byte {
	n := len(inputs)
	if n == 0 {
		return nil
	}
	results := make([][Size256]byte, n)
	for i, data := range inputs {
		results[i] = Sum256(data)
	}
	return results
}

// MerkleRoot computes the Merkle root of leaves using Blake3.
func MerkleRoot(leaves [][]byte) [Size256]byte {
	var out [Size256]byte
	n := len(leaves)
	if n == 0 {
		return out
	}

	// Hash each leaf first
	hashes := make([][Size256]byte, n)
	for i, leaf := range leaves {
		hashes[i] = Sum256(leaf)
	}

	// Build tree bottom-up
	for len(hashes) > 1 {
		nextLevel := make([][Size256]byte, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				// Hash pair
				combined := make([]byte, Size256*2)
				copy(combined[:Size256], hashes[i][:])
				copy(combined[Size256:], hashes[i+1][:])
				nextLevel[i/2] = Sum256(combined)
			} else {
				// Odd node, promote to next level
				nextLevel[i/2] = hashes[i]
			}
		}
		hashes = nextLevel
	}

	if len(hashes) > 0 {
		out = hashes[0]
	}
	return out
}

// DeriveKey derives a key from context and key material using Blake3 KDF.
func DeriveKey(context string, keyMaterial []byte) [Size256]byte {
	// Use proper Blake3 KDF: derive_key(context, key_material)
	// Combine context and key material with domain separation
	h := NewWithDomain("BLAKE3 KDF: " + context)
	h.Write(keyMaterial)
	var out [Size256]byte
	h.Reader().Read(out[:])
	return out
}

// sumXOF implements XOF by chaining hash outputs with counter.
// This matches the CGO implementation for compatibility.
func sumXOF(data []byte, outLen int) []byte {
	if outLen <= Size256 {
		hash := Sum256(data)
		return hash[:outLen]
	}

	out := make([]byte, outLen)
	// First block: hash the data directly
	first := Sum256(data)
	copy(out[:Size256], first[:])

	// Subsequent blocks: hash(data || counter)
	remaining := outLen - Size256
	counter := uint64(1)
	offset := Size256

	for remaining > 0 {
		// Create input: data || counter (little-endian)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, counter)
		input := append(data, counterBytes...)

		block := Sum256(input)
		toCopy := Size256
		if remaining < Size256 {
			toCopy = remaining
		}
		copy(out[offset:offset+toCopy], block[:toCopy])

		offset += toCopy
		remaining -= toCopy
		counter++
	}

	return out
}
