// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sha256

import (
	stdsha256 "crypto/sha256"
	"hash"
)

// Size is the output size of SHA-256 in bytes.
const Size = stdsha256.Size

// BatchThreshold is the minimum batch length at which Sum256Batch will try to
// route through GPU.
var BatchThreshold = 256

// Sum256 returns the SHA-256 hash of in.
func Sum256(in []byte) [Size]byte { return stdsha256.Sum256(in) }

// New returns a hash.Hash computing SHA-256.
func New() hash.Hash { return stdsha256.New() }

// Sum256Batch computes SHA-256 for a batch of inputs.
func Sum256Batch(inputs [][]byte) [][Size]byte {
	out := make([][Size]byte, len(inputs))
	if len(inputs) >= BatchThreshold {
		if ok, err := batchGPU(inputs, out); ok && err == nil {
			return out
		}
	}
	for i, in := range inputs {
		out[i] = stdsha256.Sum256(in)
	}
	return out
}
