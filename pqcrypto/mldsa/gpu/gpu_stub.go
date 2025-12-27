// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !luxgpu

// Package gpu provides GPU-accelerated ML-DSA operations.
// This is the stub implementation for non-CGO builds.
package gpu

import (
	"github.com/luxfi/crypto/mldsa"
)

// BatchSignThreshold is the minimum batch size for GPU acceleration.
const BatchSignThreshold = 16

// BatchVerifyThreshold is the minimum batch size for GPU verification.
const BatchVerifyThreshold = 32

// Available returns false - GPU not available without CGO.
func Available() bool {
	return false
}

// Threshold returns the batch threshold (always returns CPU threshold).
func Threshold() int {
	return BatchVerifyThreshold
}

// KeyGen generates an ML-DSA key pair (CPU fallback).
func KeyGen(mode mldsa.Mode, seed []byte) (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(nil, mode)
}

// BatchSign signs multiple messages (CPU fallback).
func BatchSign(priv *mldsa.PrivateKey, messages [][]byte) ([][]byte, error) {
	if priv == nil {
		return nil, mldsa.ErrInvalidMode
	}
	signatures := make([][]byte, len(messages))
	for i, msg := range messages {
		sig, err := priv.Sign(nil, msg, nil)
		if err != nil {
			return nil, err
		}
		signatures[i] = sig
	}
	return signatures, nil
}

// BatchVerify verifies multiple signatures (CPU fallback).
func BatchVerify(pks []*mldsa.PublicKey, sigs [][]byte, msgs [][]byte) ([]bool, error) {
	if len(pks) != len(sigs) || len(pks) != len(msgs) {
		return nil, mldsa.ErrInvalidMode
	}
	results := make([]bool, len(pks))
	for i := range pks {
		if pks[i] == nil {
			results[i] = false
			continue
		}
		results[i] = pks[i].VerifySignature(msgs[i], sigs[i])
	}
	return results, nil
}

// GPUMode returns the current GPU mode information.
func GPUMode() string {
	return "CPU fallback (no CGO)"
}

// Destroy is a no-op for non-CGO builds.
func Destroy() {}
