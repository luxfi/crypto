// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// Package gpu provides GPU-accelerated IPA/Verkle operations.
// This is the pure Go fallback when CGO is not available.
package gpu

import (
	"errors"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
)

// Thresholds for batch operations (same as CGO version for API compatibility)
const (
	MSMThreshold       = 64
	PedersenThreshold  = 32
	IPAVerifyThreshold = 16
)

// Available returns false when CGO is not available.
func Available() bool {
	return false
}

// MSM performs multi-scalar multiplication using pure Go.
// result = sum_i (scalars[i] * points[i])
func MSM(points []banderwagon.Element, scalars []fr.Element) (*banderwagon.Element, error) {
	n := len(points)
	if n == 0 || n != len(scalars) {
		return nil, errors.New("mismatched input lengths")
	}

	var result banderwagon.Element
	_, err := result.MultiExp(points, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
	return &result, err
}

// BatchMSM performs multiple MSM operations sequentially using pure Go.
func BatchMSM(pointSets [][]banderwagon.Element, scalarSets [][]fr.Element) ([]*banderwagon.Element, error) {
	n := len(pointSets)
	if n == 0 || n != len(scalarSets) {
		return nil, errors.New("mismatched input lengths")
	}

	results := make([]*banderwagon.Element, n)
	for i := 0; i < n; i++ {
		result, err := MSM(pointSets[i], scalarSets[i])
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

// PedersenCommit computes a Pedersen commitment using pure Go.
// commitment = sum_i (values[i] * basis[i])
func PedersenCommit(basis []banderwagon.Element, values []fr.Element) (*banderwagon.Element, error) {
	return MSM(basis, values)
}

// BatchPedersenCommit computes multiple Pedersen commitments sequentially.
func BatchPedersenCommit(basis []banderwagon.Element, valueSets [][]fr.Element) ([]*banderwagon.Element, error) {
	n := len(valueSets)
	if n == 0 {
		return nil, errors.New("empty value sets")
	}

	pointSets := make([][]banderwagon.Element, n)
	for i := 0; i < n; i++ {
		if len(valueSets[i]) > len(basis) {
			return nil, errors.New("value set larger than basis")
		}
		pointSets[i] = basis[:len(valueSets[i])]
	}

	return BatchMSM(pointSets, valueSets)
}

// VerkleCommitNode computes a Verkle tree internal node commitment.
// Uses width-256 Pedersen commitment optimized for Verkle trees.
func VerkleCommitNode(children []banderwagon.Element) (*banderwagon.Element, error) {
	if len(children) != 256 {
		return nil, errors.New("Verkle node requires exactly 256 children")
	}

	scalars := make([]fr.Element, 256)
	for i := 0; i < 256; i++ {
		scalars[i].SetOne()
	}

	var result banderwagon.Element
	_, err := result.MultiExp(children, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
	return &result, err
}

// Destroy is a no-op in the pure Go implementation.
func Destroy() {}
