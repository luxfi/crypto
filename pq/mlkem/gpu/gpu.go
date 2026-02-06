// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU-accelerated ML-KEM operations (stub).
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

// BatchEncaps performs batch encapsulation (stub - not GPU accelerated).
func BatchEncaps(pks interface{}, opts interface{}) ([][]byte, [][]byte, error) {
	return nil, nil, errors.New("GPU not available")
}

// BatchDecaps performs batch decapsulation (stub - not GPU accelerated).
func BatchDecaps(sk interface{}, cts [][]byte) ([][]byte, error) {
	return nil, errors.New("GPU not available")
}
