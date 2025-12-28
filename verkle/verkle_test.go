// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.

package verkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	upstream "github.com/ethereum/go-verkle"
)

// makeSingleLeafProof builds a (preStateRoot=empty, postStateRoot=after-insert)
// pair plus the corresponding VerkleProof and StateDiff for a single key/value
// insert. This produces a deterministic Verify-roundtrip that we can replay.
func makeSingleLeafProof(t *testing.T, seed uint64) BatchProof {
	t.Helper()

	// Derive a key + value from seed.
	var seedBuf [8]byte
	binary.BigEndian.PutUint64(seedBuf[:], seed)
	keyDigest := sha256.Sum256(append([]byte("verkle-kat-key"), seedBuf[:]...))
	valDigest := sha256.Sum256(append([]byte("verkle-kat-val"), seedBuf[:]...))

	preroot := upstream.New()
	preroot.Commit()
	preCommit := preroot.Commit().Bytes()

	postroot := upstream.New()
	if err := postroot.Insert(keyDigest[:], valDigest[:], nil); err != nil {
		t.Fatalf("seed=%d insert: %v", seed, err)
	}
	postroot.Commit()
	postCommit := postroot.Commit().Bytes()

	// Generate the proof using the pre/post pair.
	proof, _, _, _, err := upstream.MakeVerkleMultiProof(preroot, postroot, [][]byte{keyDigest[:]}, nil)
	if err != nil {
		t.Fatalf("seed=%d MakeVerkleMultiProof: %v", seed, err)
	}
	vp, sd, err := upstream.SerializeProof(proof)
	if err != nil {
		t.Fatalf("seed=%d SerializeProof: %v", seed, err)
	}

	return BatchProof{
		Proof:         vp,
		PreStateRoot:  bytes.Clone(preCommit[:]),
		PostStateRoot: bytes.Clone(postCommit[:]),
		StateDiff:     sd,
	}
}

// TestVerifyBatch_KAT runs 10 single-leaf Verkle proofs through the batched
// verifier and asserts each succeeds. Each (seed) produces a deterministic
// (key, value) so that this test is reproducible across runs and platforms.
func TestVerifyBatch_KAT(t *testing.T) {
	proofs := make([]BatchProof, 10)
	for i := uint64(0); i < 10; i++ {
		proofs[i] = makeSingleLeafProof(t, i+1)
	}
	if err := VerifyBatch(proofs); err != nil {
		t.Fatalf("batch verify failed: %v", err)
	}
}

func TestVerifyBatch_TamperDetected(t *testing.T) {
	bp := makeSingleLeafProof(t, 1)
	// Flip a byte in the post-state root so verification fails.
	bp.PostStateRoot = bytes.Clone(bp.PostStateRoot)
	bp.PostStateRoot[0] ^= 0xFF
	err := VerifyBatch([]BatchProof{bp})
	if err == nil {
		t.Fatal("expected verify failure for tampered post-state")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("verkle batch[0]")) {
		t.Fatalf("expected wrapped index in error, got %v", err)
	}
}

func TestVerifyBatch_Empty(t *testing.T) {
	if err := VerifyBatch(nil); err != ErrBatchLengthMismatch {
		t.Fatalf("expected ErrBatchLengthMismatch, got %v", err)
	}
}

func TestVerify_SingleSucceeds(t *testing.T) {
	bp := makeSingleLeafProof(t, 42)
	if err := Verify(bp.Proof, bp.PreStateRoot, bp.PostStateRoot, bp.StateDiff); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNodeWidthIs256(t *testing.T) {
	if NodeWidth != 256 {
		t.Fatalf("NodeWidth changed: got %d want 256", NodeWidth)
	}
}

func TestVerifyBatch_NilProof(t *testing.T) {
	err := VerifyBatch([]BatchProof{{Proof: nil}})
	if err == nil {
		t.Fatal("expected error for nil proof")
	}
	want := fmt.Sprintf("verkle batch[%d]: nil proof", 0)
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
	}
}
