// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build gpu && darwin

// Package blake3 provides Blake3 hash functions via luxcpp/crypto.
// This CGO version provides optimized hashing with automatic CPU/GPU selection.
// For GPU-only operations, use the blake3/gpu subpackage.
package blake3

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../luxcpp/crypto/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation

#include <stdint.h>
#include <stdlib.h>

// C API from luxcpp/crypto
extern void crypto_blake3(uint8_t* out, const uint8_t* in, size_t len);
extern int crypto_batch_hash(uint8_t** outs, const uint8_t* const* ins, const size_t* lens, uint32_t count, int hash_type);
extern int crypto_gpu_available(void);
extern const char* crypto_get_backend(void);
*/
import "C"

import (
	"encoding/binary"
	"unsafe"
)

const (
	// Size256 is the standard Blake3 output size
	Size256 = 32
	// Size512 is extended Blake3 output size
	Size512 = 64
	// gpuThreshold is minimum batch size for GPU acceleration
	gpuThreshold = 64
)

var (
	// useGPU indicates if GPU acceleration is available
	useGPU = C.crypto_gpu_available() != 0
)

// GPUAvailable returns true if GPU acceleration is available.
func GPUAvailable() bool {
	return useGPU
}

// Backend returns the active backend name ("Metal", "CUDA", or "CPU").
func Backend() string {
	return C.GoString(C.crypto_get_backend())
}

// Sum256 computes a 32-byte Blake3 hash.
func Sum256(data []byte) [Size256]byte {
	var out [Size256]byte
	if len(data) == 0 {
		C.crypto_blake3((*C.uint8_t)(&out[0]), nil, 0)
		return out
	}
	C.crypto_blake3(
		(*C.uint8_t)(&out[0]),
		(*C.uint8_t)(&data[0]),
		C.size_t(len(data)),
	)
	return out
}

// Sum512 computes a 64-byte Blake3 hash using XOF mode.
// Implemented as XOF by hashing with counter blocks.
func Sum512(data []byte) [Size512]byte {
	var out [Size512]byte
	xof := sumXOF(data, Size512)
	copy(out[:], xof)
	return out
}

// SumXOF computes an extendable output hash of arbitrary length.
func SumXOF(data []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	return sumXOF(data, outLen)
}

// sumXOF implements XOF by chaining hash outputs with counter.
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

// BatchSum256 computes Blake3 hashes for multiple inputs in parallel.
// More efficient than calling Sum256 repeatedly for batch operations.
func BatchSum256(inputs [][]byte) [][Size256]byte {
	n := len(inputs)
	if n == 0 {
		return nil
	}

	// For small batches, use sequential processing
	if n < gpuThreshold || !useGPU {
		results := make([][Size256]byte, n)
		for i, data := range inputs {
			results[i] = Sum256(data)
		}
		return results
	}

	// Prepare C arrays for batch processing
	outs := make([]*C.uint8_t, n)
	ins := make([]*C.uint8_t, n)
	lens := make([]C.size_t, n)

	results := make([][Size256]byte, n)
	for i, data := range inputs {
		outs[i] = (*C.uint8_t)(&results[i][0])
		if len(data) > 0 {
			ins[i] = (*C.uint8_t)(&data[0])
		}
		lens[i] = C.size_t(len(data))
	}

	// Call batch hash (hash_type 2 = BLAKE3)
	C.crypto_batch_hash(
		(**C.uint8_t)(unsafe.Pointer(&outs[0])),
		(**C.uint8_t)(unsafe.Pointer(&ins[0])),
		(*C.size_t)(&lens[0]),
		C.uint32_t(n),
		2, // BLAKE3
	)

	return results
}

// MerkleRoot computes the Merkle root of leaves using Blake3.
// This is a software implementation; for GPU-accelerated version, use blake3/gpu.
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
	// Combine context and key material with domain separation
	input := append([]byte(context), 0x00)
	input = append(input, keyMaterial...)
	return Sum256(input)
}
