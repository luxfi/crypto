// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// Package gpu provides Verkle tree operations.
// Pure Go implementation when CGO is not available.
package gpu

import (
	"errors"

	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/ethereum/go-verkle"
)

// GPU acceleration thresholds (same as CGO version for API compatibility)
const (
	MinPolyDegreeGPU     = 4
	BatchCommitThreshold = 8
)

// Available returns false when CGO is not available.
func Available() bool {
	return false
}

// CommitToPoly performs polynomial commitment using pure Go.
func CommitToPoly(poly []fr.Element) (*verkle.Point, error) {
	if len(poly) == 0 {
		return nil, errors.New("empty polynomial")
	}
	cfg := verkle.GetConfig()
	return cfg.CommitToPoly(poly, 0), nil
}

// BatchCommitToPoly performs sequential polynomial commitments.
func BatchCommitToPoly(polys [][]fr.Element) ([]*verkle.Point, error) {
	if len(polys) == 0 {
		return nil, errors.New("empty polynomial batch")
	}
	results := make([]*verkle.Point, len(polys))
	cfg := verkle.GetConfig()
	for i, poly := range polys {
		results[i] = cfg.CommitToPoly(poly, 0)
	}
	return results, nil
}

// VerifyProof is not available without CGO - use go-verkle directly.
func VerifyProof(
	commitment *verkle.Point,
	proof []byte,
	point fr.Element,
	evaluation fr.Element,
) (bool, error) {
	return false, errors.New("GPU verification not available, use go-verkle")
}

// BatchVerifyProofs is not available without CGO.
func BatchVerifyProofs(
	commitments []*verkle.Point,
	proofs [][]byte,
	points []fr.Element,
	evaluations []fr.Element,
) ([]bool, error) {
	return nil, errors.New("GPU batch verification not available, use go-verkle")
}

// Destroy is a no-op in pure Go.
func Destroy() {}
