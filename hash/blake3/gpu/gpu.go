// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && metal && darwin

// Package gpu provides GPU-accelerated Blake3 hash functions via Metal.
// This package links to luxcpp/crypto for hardware acceleration.
// The C++ library handles automatic fallback to CPU when GPU is unavailable.
package gpu

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../../luxcpp/crypto/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../../luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation

#include <stdint.h>
#include <stdlib.h>

// C API from luxcpp/crypto
extern void crypto_blake3(uint8_t* out, const uint8_t* in, size_t len);
extern int crypto_batch_hash(uint8_t** outs, const uint8_t* const* ins, const size_t* lens, uint32_t count, int hash_type);
extern int crypto_gpu_available(void);
extern const char* crypto_get_backend(void);

// Metal-specific Blake3 functions
extern int metal_blake3_hash256(const uint8_t* data, uint32_t len, uint8_t* out);
extern int metal_blake3_hash512(const uint8_t* data, uint32_t len, uint8_t* out);
extern int metal_blake3_xof(const uint8_t* data, uint32_t inLen, uint8_t* out, uint32_t outLen);
extern int metal_blake3_merkle_root(const uint8_t* leaves, uint32_t numLeaves, uint8_t* out);
extern int metal_blake3_derive_key(const uint8_t* context, uint32_t contextLen, const uint8_t* key, uint32_t keyLen, uint8_t* out);
*/
import "C"

import (
	"unsafe"
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
	return C.crypto_gpu_available() != 0
}

// Backend returns the active backend name ("Metal", "CUDA", or "CPU").
func Backend() string {
	return C.GoString(C.crypto_get_backend())
}

// Sum256 computes a 32-byte Blake3 hash using GPU if available.
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

// Sum512 computes a 64-byte Blake3 hash using Metal GPU.
func Sum512(data []byte) [Size512]byte {
	var out [Size512]byte
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(&data[0])
	}
	C.metal_blake3_hash512(dataPtr, C.uint32_t(len(data)), (*C.uint8_t)(&out[0]))
	return out
}

// SumXOF computes an extendable output hash of arbitrary length.
func SumXOF(data []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	out := make([]byte, outLen)
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(&data[0])
	}
	C.metal_blake3_xof(
		dataPtr,
		C.uint32_t(len(data)),
		(*C.uint8_t)(&out[0]),
		C.uint32_t(outLen),
	)
	return out
}

// BatchSum256 computes Blake3 hashes for multiple inputs in parallel on GPU.
// More efficient than calling Sum256 repeatedly for batch operations.
func BatchSum256(inputs [][]byte) [][Size256]byte {
	n := len(inputs)
	if n == 0 {
		return nil
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

// MerkleRoot computes the Merkle root of leaves using GPU-accelerated Blake3.
func MerkleRoot(leaves [][]byte) [Size256]byte {
	var out [Size256]byte
	n := len(leaves)
	if n == 0 {
		return out
	}

	// Flatten leaves to contiguous buffer
	leafData := make([]byte, n*Size256)
	for i, leaf := range leaves {
		hash := Sum256(leaf)
		copy(leafData[i*Size256:], hash[:])
	}

	C.metal_blake3_merkle_root(
		(*C.uint8_t)(&leafData[0]),
		C.uint32_t(n),
		(*C.uint8_t)(&out[0]),
	)
	return out
}

// DeriveKey derives a key from context and key material using Blake3 KDF.
func DeriveKey(context string, keyMaterial []byte) [Size256]byte {
	var out [Size256]byte
	contextBytes := []byte(context)

	var contextPtr, keyPtr *C.uint8_t
	if len(contextBytes) > 0 {
		contextPtr = (*C.uint8_t)(&contextBytes[0])
	}
	if len(keyMaterial) > 0 {
		keyPtr = (*C.uint8_t)(&keyMaterial[0])
	}

	C.metal_blake3_derive_key(
		contextPtr, C.uint32_t(len(contextBytes)),
		keyPtr, C.uint32_t(len(keyMaterial)),
		(*C.uint8_t)(&out[0]),
	)
	return out
}
