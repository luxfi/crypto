// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keccak

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// batchGPU returns (true, nil) when it produced output on the GPU,
// (false, nil) when the GPU was not eligible (callers must fall through),
// or (true, err) when GPU dispatch was attempted and failed. Today this
// helper is non-CGO compatible because lux/accel itself returns
// ErrNoBackends in that mode — the caller treats both shapes as "fall
// back to vanilla".
func batchGPU(inputs [][]byte, out [][Size]byte) (handled bool, err error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}

	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	// Pad inputs to a fixed width for batch dispatch. The accel API accepts
	// [N, W] uint8 tensors. W must equal the longest input rounded up.
	width := 0
	for _, in := range inputs {
		if len(in) > width {
			width = len(in)
		}
	}
	if width == 0 {
		// All inputs empty: still well-defined per Keccak.
		empty := sumVanilla(nil)
		for i := range out {
			out[i] = empty
		}
		return true, nil
	}

	flat := make([]uint8, len(inputs)*width)
	for i, in := range inputs {
		copy(flat[i*width:(i+1)*width], in)
	}
	inT, err := accel.NewTensorWithData[uint8](sess, []int{len(inputs), width}, flat)
	if err != nil {
		return false, nil
	}
	defer inT.Close()

	outT, err := accel.NewTensor[uint8](sess, []int{len(inputs), Size})
	if err != nil {
		return false, nil
	}
	defer outT.Close()

	if err := sess.Crypto().Keccak256(inT.Untyped(), outT.Untyped()); err != nil {
		return false, nil
	}

	bytes, err := outT.ToSlice()
	if err != nil {
		return false, nil
	}
	for i := range out {
		copy(out[i][:], bytes[i*Size:(i+1)*Size])
	}
	return true, nil
}
