// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	"hash"
	"io"

	"github.com/zeebo/blake3"
)

// Size is the default output size of BLAKE3 in bytes.
const Size = 32

// KeySize is the required key length for the keyed-hash mode.
const KeySize = 32

// BatchThreshold is the minimum batch length at which HashBatch will try to
// route through GPU (lux/accel). Below this threshold the vanilla path is
// always faster (PCIe round-trip dominates).
//
// Tuned to match the keccak/sha256 packages; expose as a knob so downstream
// profilers can override per workload.
var BatchThreshold = 256

// Hash returns the BLAKE3-256 hash of in. Allocations: 1.
func Hash(in []byte) [Size]byte {
	return blake3.Sum256(in)
}

// HashHex is a convenience that returns a hex string of Hash(in).
func HashHex(in []byte) string {
	h := Hash(in)
	const hex = "0123456789abcdef"
	out := make([]byte, 2*Size)
	for i, b := range h {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return string(out)
}

// New returns a hash.Hash computing BLAKE3-256.
//
// Use Hash when you have a contiguous input; New when you need to write
// incrementally.
func New() hash.Hash {
	return blake3.New()
}

// NewKeyed returns a hash.Hash computing keyed BLAKE3 (MAC mode).
// key must be exactly KeySize (32) bytes.
func NewKeyed(key []byte) (hash.Hash, error) {
	return blake3.NewKeyed(key)
}

// KeyedHash computes keyed BLAKE3 over in with the given 32-byte key.
// Returns an error if the key is not exactly KeySize bytes.
func KeyedHash(key, in []byte) ([Size]byte, error) {
	var out [Size]byte
	h, err := blake3.NewKeyed(key)
	if err != nil {
		return out, err
	}
	h.Write(in)
	h.Sum(out[:0])
	return out, nil
}

// DeriveKey derives a key of len(out) bytes from material in the given
// hardcoded context (RFC-style KDF mode). Context strings should be
// hardcoded constants per the BLAKE3 spec, e.g.
// "example.com 2026-04-27 session tokens v1".
func DeriveKey(context string, material, out []byte) {
	blake3.DeriveKey(context, material, out)
}

// Reader returns an io.Reader yielding the BLAKE3 XOF stream of in. The
// stream is unbounded and seekable.
func Reader(in []byte) io.ReadSeeker {
	h := blake3.New()
	h.Write(in)
	return h.Digest()
}

// Concat returns the BLAKE3-256 hash of the concatenation of all inputs,
// without allocating an intermediate buffer.
func Concat(inputs ...[]byte) [Size]byte {
	h := blake3.New()
	for _, b := range inputs {
		h.Write(b)
	}
	var out [Size]byte
	h.Sum(out[:0])
	return out
}

// HashBatch computes BLAKE3-256 for a batch of inputs.
//
// When the batch is large enough and the GPU backend is available the
// computation runs on the GPU; otherwise it runs on the CPU. The output is
// always byte-identical to repeated calls to Hash.
func HashBatch(inputs [][]byte) [][Size]byte {
	out := make([][Size]byte, len(inputs))
	if len(inputs) == 0 {
		return out
	}

	if len(inputs) >= BatchThreshold {
		if ok, err := batchGPU(inputs, out); ok && err == nil {
			return out
		}
	}

	for i, in := range inputs {
		out[i] = blake3.Sum256(in)
	}
	return out
}
