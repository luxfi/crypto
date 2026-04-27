// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.

package multiproof

import (
	"testing"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
	"github.com/luxfi/crypto/ipa/common"
	"github.com/luxfi/crypto/ipa/ipa"
	"github.com/luxfi/crypto/ipa/test_helper"
)

// makeBatchProof produces a single BatchProof for testing using a known
// polynomial/evaluation point pair. Each call uses a fresh transcript so
// the proof bytes match what a non-batched caller would produce.
func makeBatchProof(t *testing.T, conf *ipa.IPAConfig, seed uint64, z uint8) BatchProof {
	t.Helper()
	// Build a deterministic poly from seed.
	var coeffs []uint64
	for i := uint64(0); i < 16; i++ {
		coeffs = append(coeffs, seed+i)
	}
	poly := test_helper.TestPoly256(coeffs...)
	C := conf.Commit(poly)
	tr := common.NewTranscript("batch-kat")
	mp, err := CreateMultiProof(tr, conf, []*banderwagon.Element{&C}, [][]fr.Element{poly}, []uint8{z})
	if err != nil {
		t.Fatal(err)
	}
	y := poly[z]
	return BatchProof{
		Proof: mp,
		Cs:    []*banderwagon.Element{&C},
		Ys:    []*fr.Element{&y},
		Zs:    []uint8{z},
	}
}

// TestCheckMultiProofBatch_KAT runs 10 batched proofs through the verifier
// and asserts each one succeeds. The matrix of (seed, z) covers a healthy
// range of polynomial domains and evaluation points.
func TestCheckMultiProofBatch_KAT(t *testing.T) {
	conf, err := ipa.NewIPASettings()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		seed uint64
		z    uint8
	}{
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 7},
		{5, 31},
		{6, 63},
		{7, 127},
		{8, 200},
		{9, 254},
		{10, 255},
	}
	proofs := make([]BatchProof, len(cases))
	for i, tc := range cases {
		proofs[i] = makeBatchProof(t, conf, tc.seed, tc.z)
	}
	if err := CheckMultiProofBatch([]byte("batch-kat"), conf, proofs); err != nil {
		t.Fatalf("batch verify failed: %v", err)
	}
}

func TestCheckMultiProofBatch_TamperDetected(t *testing.T) {
	conf, err := ipa.NewIPASettings()
	if err != nil {
		t.Fatal(err)
	}
	bp := makeBatchProof(t, conf, 1, 0)
	// Tamper with the y value.
	var bogus fr.Element
	bogus.SetUint64(0xDEADBEEF)
	bp.Ys = []*fr.Element{&bogus}
	if err := CheckMultiProofBatch([]byte("batch-kat"), conf, []BatchProof{bp}); err == nil {
		t.Fatal("expected error from tampered proof")
	}
}

func TestCheckMultiProofBatch_LengthMismatch(t *testing.T) {
	conf, err := ipa.NewIPASettings()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckMultiProofBatch([]byte("x"), conf, nil); err != ErrBatchLengthMismatch {
		t.Fatalf("expected ErrBatchLengthMismatch on empty input, got %v", err)
	}
}
