// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

func batchGPU(pubs []PublicKey, msgs [][]byte, sigs [][]byte, out []bool) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	n := len(pubs)
	width := 0
	for _, m := range msgs {
		if len(m) > width {
			width = len(m)
		}
	}
	if width == 0 {
		width = 1 // accel rejects zero-width tensors
	}

	mFlat := make([]uint8, n*width)
	for i, m := range msgs {
		copy(mFlat[i*width:(i+1)*width], m)
	}
	pFlat := make([]uint8, n*PublicKeySize)
	for i, p := range pubs {
		copy(pFlat[i*PublicKeySize:(i+1)*PublicKeySize], p)
	}
	sFlat := make([]uint8, n*SignatureSize)
	for i, s := range sigs {
		copy(sFlat[i*SignatureSize:(i+1)*SignatureSize], s)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, width}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	sT, err := accel.NewTensorWithData[uint8](sess, []int{n, SignatureSize}, sFlat)
	if err != nil {
		return false, nil
	}
	defer sT.Close()
	pT, err := accel.NewTensorWithData[uint8](sess, []int{n, PublicKeySize}, pFlat)
	if err != nil {
		return false, nil
	}
	defer pT.Close()
	rT, err := accel.NewTensor[uint8](sess, []int{n})
	if err != nil {
		return false, nil
	}
	defer rT.Close()

	if err := sess.Crypto().Ed25519VerifyBatch(mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped()); err != nil {
		return false, nil
	}
	bytes, err := rT.ToSlice()
	if err != nil {
		return false, nil
	}
	for i, b := range bytes {
		out[i] = b == 1
	}
	return true, nil
}
