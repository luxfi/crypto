// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sha256

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

func batchGPU(inputs [][]byte, out [][Size]byte) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	width := 0
	for _, in := range inputs {
		if len(in) > width {
			width = len(in)
		}
	}
	if width == 0 {
		empty := Sum256(nil)
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

	if err := sess.Crypto().SHA256(inT.Untyped(), outT.Untyped()); err != nil {
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
