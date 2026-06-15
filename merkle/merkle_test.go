// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package merkle

import (
	"encoding/hex"
	"testing"
)

// canonicalLeaf reproduces the synthetic leaf digest the normative spec
// (lux_merkle_fold.hpp KAT block) documents: leaf_i[k] = (i*13 + k) & 0xFF.
func canonicalLeaf(i int) [Size]byte {
	var d [Size]byte
	for k := 0; k < Size; k++ {
		d[k] = byte((i*13 + k) & 0xFF)
	}
	return d
}

// canonicalLeaves returns the first n canonical synthetic leaves.
func canonicalLeaves(n int) [][Size]byte {
	leaves := make([][Size]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = canonicalLeaf(i)
	}
	return leaves
}

func hexRoot(t *testing.T, leaves [][Size]byte) string {
	t.Helper()
	r := Root(leaves)
	return hex.EncodeToString(r[:])
}

// TestCanonicalRoots reproduces the ground-truth Merkle roots embedded in the
// normative spec's KAT block, byte-for-byte, over the same synthetic leaves.
//
// Source: lux-private/gpu-kernels/backends/common/lux_merkle_fold.hpp, §"KNOWN-
// ANSWER TEST VECTORS" — the `merkle` rows.
func TestCanonicalRoots(t *testing.T) {
	vectors := []struct {
		n    int
		want string
	}{
		{0, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"}, // == keccak256("")
		{1, "683ea6c3fe5897c14793af914188cf6213ae23055d2db482662fb2d34397b46c"}, // == LeafHash(leaf_0)
		{2, "5f53cd7134abee151bf652e66142fd021f08e6f7e6ba5c6c744aa84db37c842a"},
		{3, "b5b7ea7803828c9676bc004498ea1f9e9cb9580bddaf06bafc4750686d209d7e"},
		{4, "9a443c07f5bdfbf085a73ee3c9177681fb89aae55d0f830de93ee6e8ced5be5f"},
		{5, "1328bf1c0aa1e5f69b5151216729310cb3eff2284c2331096abf1f42227d97a0"},
		{8, "fa78e524bec74f936f3571ddbcfdae9eacc15d05f3cff7de3ed8a0124356067f"},
	}
	for _, v := range vectors {
		got := hexRoot(t, canonicalLeaves(v.n))
		if got != v.want {
			t.Errorf("Root(n=%d):\n got  %s\n want %s", v.n, got, v.want)
		}
	}
}

// TestEmptyRoot pins the empty-set root to keccak256("") (the canonical
// Keccak-256 empty-data hash, identical to the EVM empty-data hash). This also
// guards against an accidental sha3.Sum256 (FIPS-202) swap, which would yield
// a different digest.
func TestEmptyRoot(t *testing.T) {
	const want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got := hex.EncodeToString(mustBytes(EmptyRoot())); got != want {
		t.Errorf("EmptyRoot:\n got  %s\n want %s", got, want)
	}
	// Root over a nil/empty slice must equal EmptyRoot.
	if got := hexRoot(t, nil); got != want {
		t.Errorf("Root(nil):\n got  %s\n want %s", got, want)
	}
}

// TestSingleLeaf confirms n==1 returns LeafHash(leaves[0]) with no internal
// node wrapping.
func TestSingleLeaf(t *testing.T) {
	const want = "683ea6c3fe5897c14793af914188cf6213ae23055d2db482662fb2d34397b46c"
	leaf0 := canonicalLeaf(0)
	if got := hex.EncodeToString(mustBytes(LeafHash(leaf0))); got != want {
		t.Errorf("LeafHash(leaf_0):\n got  %s\n want %s", got, want)
	}
	if got := hexRoot(t, [][Size]byte{leaf0}); got != want {
		t.Errorf("Root([leaf_0]):\n got  %s\n want %s", got, want)
	}
}

// TestLoneRightPromotion verifies the worked n=3 shape from §3:
// Root = node_hash( node_hash(L0,L1), L2 ), where L2 (the lone leaf hash) is
// promoted UNCHANGED — not hashed with itself, not duplicated.
func TestLoneRightPromotion(t *testing.T) {
	leaves := canonicalLeaves(3)
	l0 := LeafHash(leaves[0])
	l1 := LeafHash(leaves[1])
	l2 := LeafHash(leaves[2]) // promoted unchanged at level 0
	want := NodeHash(NodeHash(l0, l1), l2)
	got := Root(leaves)
	if got != want {
		t.Errorf("n=3 shape:\n got  %x\n want %x", got, want)
	}
	// Negative control: duplicate-last (Bitcoin CVE-2012-2459) would be
	// node_hash( node_hash(L0,L1), node_hash(L2,L2) ) and must NOT match.
	dup := NodeHash(NodeHash(l0, l1), NodeHash(l2, l2))
	if got == dup {
		t.Error("n=3 root matched the rejected duplicate-last shape")
	}
}

// TestRootDoesNotMutateInput guards the documented "leaves is not modified"
// contract.
func TestRootDoesNotMutateInput(t *testing.T) {
	leaves := canonicalLeaves(5)
	before := canonicalLeaves(5)
	_ = Root(leaves)
	for i := range leaves {
		if leaves[i] != before[i] {
			t.Fatalf("Root mutated leaves[%d]", i)
		}
	}
}

func mustBytes(a [Size]byte) []byte { return a[:] }
