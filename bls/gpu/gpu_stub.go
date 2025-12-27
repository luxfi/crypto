// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// Package gpu provides GPU-accelerated BLS12-381 operations.
// This is the stub implementation when GPU acceleration is not available.
package gpu

import (
	"github.com/luxfi/crypto/bls"
)

// Thresholds for GPU batch operations
const (
	BatchVerifyThreshold    = 64  // Min signatures for GPU batch verify
	BatchAggregateThreshold = 128 // Min items for GPU aggregation
)

// Available returns true if GPU acceleration is available for BLS.
func Available() bool {
	return false
}

// BatchVerify verifies multiple BLS signatures.
// Falls back to sequential verification when GPU is unavailable.
func BatchVerify(pks []*bls.PublicKey, sigs []*bls.Signature, msgs [][]byte) ([]bool, error) {
	n := len(pks)
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = bls.Verify(pks[i], sigs[i], msgs[i])
	}
	return results, nil
}

// AggregateSignatures aggregates multiple BLS signatures into one.
func AggregateSignatures(sigs []*bls.Signature) (*bls.Signature, error) {
	return bls.AggregateSignatures(sigs)
}

// AggregatePublicKeys aggregates multiple BLS public keys into one.
func AggregatePublicKeys(pks []*bls.PublicKey) (*bls.PublicKey, error) {
	return bls.AggregatePublicKeys(pks)
}

// VerifyAggregate verifies an aggregated signature against multiple messages and keys.
func VerifyAggregate(pks []*bls.PublicKey, sig *bls.Signature, msgs [][]byte) bool {
	// Simple fallback - for production, use proper aggregate verification
	for i := range pks {
		if !bls.Verify(pks[i], sig, msgs[i]) {
			return false
		}
	}
	return true
}
