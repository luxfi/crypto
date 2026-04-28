// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
//
// Package verkle hosts the canonical Lux implementation of Verkle trees and
// the IPA-based proof system. This file exposes the batched verify entry
// point used by downstream chains and by the GPU-accelerated proof driver.
//
// A batched verify takes a slice of (proof, pre-root, post-root, state-diff)
// tuples and runs each one through the package's Verify function in
// lockstep. The shape is the contract; the body is what an MSM-batched
// verifier will replace once the curve arithmetic is in place.

package verkle

import (
	"errors"
	"fmt"
)

// ErrBatchLengthMismatch is returned by VerifyBatch when called with no
// proofs. Callers must pass at least one BatchProof; an empty slice is a
// programmer error, not a successful verification of nothing.
var ErrBatchLengthMismatch = errors.New("verkle: batch slice length mismatch")

// BatchProof bundles a single Verkle proof with the public roots and
// state diff needed to verify it. A []BatchProof is the canonical input
// shape for VerifyBatch.
type BatchProof struct {
	Proof         *VerkleProof
	PreStateRoot  []byte
	PostStateRoot []byte
	StateDiff     StateDiff
}

// VerifyBatch verifies many Verkle proofs in lockstep. Each proof is
// checked independently with Verify; this is a structural batch (one
// MSM per proof, no proof-randomized accumulation yet).
//
// Returns nil on full success, ErrBatchLengthMismatch on empty input, or
// a wrapped error from the first failing proof tagged with its index.
func VerifyBatch(proofs []BatchProof) error {
	if len(proofs) == 0 {
		return ErrBatchLengthMismatch
	}
	for i, p := range proofs {
		if p.Proof == nil {
			return fmt.Errorf("verkle batch[%d]: nil proof", i)
		}
		if err := Verify(p.Proof, p.PreStateRoot, p.PostStateRoot, p.StateDiff); err != nil {
			return fmt.Errorf("verkle batch[%d]: %w", i, err)
		}
	}
	return nil
}
