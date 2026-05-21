// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// HQC is code-based (Hamming Quasi-Cyclic): the hot path is GF(2)^N
// polynomial multiplication + Reed-Muller / Reed-Solomon decoding, NOT
// the integer-mod-q NTT that backs ML-KEM/ML-DSA/Pulsar. Until accel
// publishes GF(2)^N-polymul and Reed-Solomon decode kernels, HQC GPU
// dispatch falls through to the PQClean CGO backend.
//
// This file mirrors the API surface of crypto/mlkem/gpu.go so that
// the backend selector can resolve GPU consistently across all KEMs;
// today the batch* functions return false (no-op) and the caller
// transparently falls back to CPU.
//
// To activate GPU dispatch here:
//   1. Add GF2N polymul + Reed-Solomon decode kernels to
//      luxfi/mlx/src (Metal + CUDA + WebGPU).
//   2. Expose them through accel.LatticeOps (e.g. HQCEncapsBatch,
//      HQCDecapsBatch) following the KyberEncapsBatch pattern.
//   3. Implement the body of batchEncapsulateGPU / batchDecapsulateGPU
//      below using sess.Lattice().HQCEncapsBatch / HQCDecapsBatch.

// batchEncapsulateGPU attempts GPU-batched HQC encapsulation. Currently
// always returns false (no GPU kernels available), forcing CPU fallback.
// Wired into the backend selector for consistency with other KEMs.
func batchEncapsulateGPU(pubs []*PublicKey, cts []*Ciphertext, sss [][]byte) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}
	// accel.LatticeOps does not publish GF(2)^N polymul kernels;
	// HQC stays CPU-bound until those land. See file-level comment.
	_ = sess
	_ = pubs
	_ = cts
	_ = sss
	return false, nil
}

// batchDecapsulateGPU attempts GPU-batched HQC decapsulation. Currently
// always returns false (no GPU kernels available), forcing CPU fallback.
func batchDecapsulateGPU(sks []*PrivateKey, cts []*Ciphertext, sss [][]byte) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}
	_ = sess
	_ = sks
	_ = cts
	_ = sss
	return false, nil
}
