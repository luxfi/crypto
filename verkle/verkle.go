// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
//
// Package verkle re-exports the go-verkle library under the luxfi/crypto
// namespace so that downstream packages (luxfi/geth, luxfi/node, etc.)
// never import ethereum/* directly.
//
// In addition to the bare re-export, this package exposes a small batched
// Verify API. A batched verify is a verify that takes a slice of (proof,
// pre-root, post-root, state-diff) tuples and runs each one through the
// upstream verifier in lockstep. The shape matches what the C++ port and
// the eventual Metal/CUDA driver consume.

package verkle

import (
	"errors"
	"fmt"

	upstream "github.com/ethereum/go-verkle"
)

// --- Type aliases ---

type (
	VerkleNode     = upstream.VerkleNode
	InternalNode   = upstream.InternalNode
	LeafNode       = upstream.LeafNode
	Empty          = upstream.Empty
	Point          = upstream.Point
	Fr             = upstream.Fr
	VerkleProof    = upstream.VerkleProof
	StateDiff      = upstream.StateDiff
	NodeResolverFn = upstream.NodeResolverFn
	IPAConfig      = upstream.IPAConfig
	Proof          = upstream.Proof
)

// --- Constants ---

const NodeWidth = upstream.NodeWidth

// --- Functions ---

var (
	ParseNode             = upstream.ParseNode
	New                   = upstream.New
	ToDot                 = upstream.ToDot
	GetConfig             = upstream.GetConfig
	MakeVerkleMultiProof  = upstream.MakeVerkleMultiProof
	SerializeProof        = upstream.SerializeProof
	HashPointToBytes      = upstream.HashPointToBytes
	FromLEBytes           = upstream.FromLEBytes
	FromBytes             = upstream.FromBytes
	DeserializeProof      = upstream.DeserializeProof
	MergeTrees            = upstream.MergeTrees
	BatchNewLeafNode      = upstream.BatchNewLeafNode
	PreStateTreeFromProof = upstream.PreStateTreeFromProof
	Verify                = upstream.Verify
)

// ErrBatchLengthMismatch is returned when VerifyBatch sees inputs whose
// outer slices disagree on length.
var ErrBatchLengthMismatch = errors.New("verkle: batch slice length mismatch")

// BatchProof bundles a single Verkle proof with the public roots and
// state diff needed to verify it. A BatchProofs slice is the canonical
// input shape for the batched verifier.
type BatchProof struct {
	Proof         *VerkleProof
	PreStateRoot  []byte
	PostStateRoot []byte
	StateDiff     StateDiff
}

// VerifyBatch verifies many Verkle proofs in lockstep. Each proof is checked
// independently with the upstream Verify function; this is a structural batch
// (one MSM per proof, no proof-randomized accumulation yet). The shape is
// the contract; the body is what the GPU driver will replace with batched
// MSM once the curve arithmetic is in place.
//
// Returns nil on full success, ErrBatchLengthMismatch on empty input, or a
// wrapped error from the first failing proof (with its index).
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
