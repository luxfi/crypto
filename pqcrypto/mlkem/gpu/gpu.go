// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !luxgpu

// Package gpu provides ML-KEM operations with optional GPU acceleration.
// This is the stub implementation for non-CGO builds.
package gpu

import (
	"crypto/rand"
	"io"

	"github.com/luxfi/crypto/mlkem"
)

// BatchEncapsThreshold is the minimum batch size for GPU encapsulation.
const BatchEncapsThreshold = 16

// BatchDecapsThreshold is the minimum batch size for GPU decapsulation.
const BatchDecapsThreshold = 16

// Available returns false - GPU not available without CGO.
func Available() bool {
	return false
}

// Threshold returns the batch threshold.
func Threshold() int {
	return BatchEncapsThreshold
}

// KeyGen generates an ML-KEM key pair (CPU fallback).
func KeyGen(mode mlkem.Mode, reader io.Reader) (*mlkem.PublicKey, *mlkem.PrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	return mlkem.GenerateKeyPair(reader, mode)
}

// BatchEncaps performs batch encapsulation (CPU fallback).
func BatchEncaps(pks []*mlkem.PublicKey, reader io.Reader) ([][]byte, [][]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	ciphertexts := make([][]byte, len(pks))
	sharedSecrets := make([][]byte, len(pks))
	for i, pk := range pks {
		if pk == nil {
			return nil, nil, mlkem.ErrInvalidKeySize
		}
		ct, ss, err := pk.Encapsulate(reader)
		if err != nil {
			return nil, nil, err
		}
		ciphertexts[i] = ct
		sharedSecrets[i] = ss
	}
	return ciphertexts, sharedSecrets, nil
}

// BatchDecaps performs batch decapsulation (CPU fallback).
func BatchDecaps(sk *mlkem.PrivateKey, ciphertexts [][]byte) ([][]byte, error) {
	if sk == nil {
		return nil, mlkem.ErrInvalidKeySize
	}
	sharedSecrets := make([][]byte, len(ciphertexts))
	for i, ct := range ciphertexts {
		ss, err := sk.Decapsulate(ct)
		if err != nil {
			return nil, err
		}
		sharedSecrets[i] = ss
	}
	return sharedSecrets, nil
}

// GPUMode returns the current GPU mode information.
func GPUMode() string {
	return "CPU fallback (no CGO)"
}

// Destroy is a no-op for non-CGO builds.
func Destroy() {}
