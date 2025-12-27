// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU-accelerated ML-DSA operations.
// Returns false for Available() when GPU hardware is not present.
package gpu

// Available returns whether GPU acceleration is available.
func Available() bool {
	return false
}
