// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
//
// Package verkle re-exports the go-verkle library under the luxfi/crypto
// namespace so that downstream packages (luxfi/geth, luxfi/node, etc.)
// never import ethereum/* directly.

package verkle

import (
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
	Proof = upstream.Proof
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
)
