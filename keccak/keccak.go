// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keccak

import (
	"hash"
	"sync"

	"github.com/luxfi/crypto/backend"
	"golang.org/x/crypto/sha3"
)

// Size is the output size of Keccak-256 in bytes.
const Size = 32

// BatchThreshold is the minimum batch length at which Sum256Batch will try to
// route through GPU (lux/accel). Below this threshold the vanilla path is
// always faster (PCIe round-trip dominates).
//
// Tuned empirically on Apple M1 Max and NVIDIA A100; expose as a knob so
// downstream profilers can override per workload.
var BatchThreshold = 256

var pool = sync.Pool{
	New: func() any { return sha3.NewLegacyKeccak256().(hash.Hash) },
}

// Sum256 returns the Keccak-256 hash of in. Allocations: 1.
func Sum256(in []byte) [Size]byte {
	switch backend.Resolve(false, false) {
	// Single-input keccak: GPU dispatch is uneconomic; cgo path identical to
	// vanilla today (golang.org/x/crypto/sha3 is asm-accelerated). One path.
	default:
		return sumVanilla(in)
	}
}

// Sum256Hex is a convenience that returns a hex string.
func Sum256Hex(in []byte) string {
	h := Sum256(in)
	const hex = "0123456789abcdef"
	out := make([]byte, 2*Size)
	for i, b := range h {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return string(out)
}

// New returns a hash.Hash computing Keccak-256.
//
// Use Sum256 when you have a contiguous input; New when you need to write
// incrementally.
func New() hash.Hash {
	return sha3.NewLegacyKeccak256()
}

// Concat returns the Keccak-256 hash of the concatenation of all inputs,
// without allocating an intermediate buffer.
func Concat(inputs ...[]byte) [Size]byte {
	h := pool.Get().(hash.Hash)
	defer pool.Put(h)
	h.Reset()
	for _, b := range inputs {
		h.Write(b)
	}
	var out [Size]byte
	h.Sum(out[:0])
	return out
}

// Sum256Batch computes Keccak-256 for a batch of inputs.
//
// When the batch is large enough and the GPU backend is available the
// computation runs on the GPU; otherwise it runs on the CPU. The output is
// always byte-identical to repeated calls to Sum256.
func Sum256Batch(inputs [][]byte) [][Size]byte {
	out := make([][Size]byte, len(inputs))
	if len(inputs) == 0 {
		return out
	}

	// GPU path is gated on backend resolution AND batch size.
	if len(inputs) >= BatchThreshold {
		if ok, err := batchGPU(inputs, out); ok && err == nil {
			return out
		}
	}

	for i, in := range inputs {
		out[i] = sumVanilla(in)
	}
	return out
}

func sumVanilla(in []byte) [Size]byte {
	h := pool.Get().(hash.Hash)
	defer pool.Put(h)
	h.Reset()
	h.Write(in)
	var out [Size]byte
	h.Sum(out[:0])
	return out
}
