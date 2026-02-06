// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU-accelerated cryptographic operations (stub).
package gpu

import "errors"

// HashType represents the type of hash function to use.
type HashType int

const (
	HashTypeSHA3_256 HashType = iota
	HashTypeSHA256
	HashTypeBlake3
)

// GPUAvailable returns whether GPU acceleration is available.
func GPUAvailable() bool {
	return false
}

// GetBackend returns the GPU backend name.
func GetBackend() string {
	return "none"
}

// SHA3_256 computes SHA3-256 hash (stub - not GPU accelerated).
func SHA3_256(input []byte) []byte {
	// Stub: return zeroes
	return make([]byte, 32)
}

// BatchHash computes batch hashes (stub - not GPU accelerated).
func BatchHash(inputs [][]byte, hashType HashType) ([][]byte, error) {
	return nil, errors.New("GPU not available")
}

// ThresholdContext represents a threshold signature context.
type ThresholdContext struct {
	threshold    uint32
	totalSigners uint32
}

// NewThresholdContext creates a new threshold context.
func NewThresholdContext(threshold, totalSigners uint32) (*ThresholdContext, error) {
	return &ThresholdContext{
		threshold:    threshold,
		totalSigners: totalSigners,
	}, nil
}

// Close releases resources.
func (c *ThresholdContext) Close() {}

// PartialSign creates a partial signature.
func (c *ThresholdContext) PartialSign(index uint32, share, msg []byte) ([]byte, error) {
	return nil, errors.New("GPU not available")
}

// Combine combines partial signatures.
func (c *ThresholdContext) Combine(partialSigs [][]byte, indices []uint32) ([]byte, error) {
	return nil, errors.New("GPU not available")
}
