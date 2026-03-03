// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU-accelerated ML-KEM operations.
// Returns false for Available() when GPU hardware is not present.
package gpu

import "errors"

// Available returns whether GPU acceleration is available.
func Available() bool {
	return false
}

// Threshold returns the minimum batch size for GPU acceleration.
func Threshold() int {
	return 100
}

// BatchEncaps performs batch encapsulation. Returns error when GPU is not available.
func BatchEncaps(pks interface{}, opts interface{}) ([][]byte, [][]byte, error) {
	return nil, nil, errors.New("GPU not available")
}

// BatchDecaps performs batch decapsulation. Returns error when GPU is not available.
func BatchDecaps(sk interface{}, cts [][]byte) ([][]byte, error) {
	return nil, errors.New("GPU not available")
}
