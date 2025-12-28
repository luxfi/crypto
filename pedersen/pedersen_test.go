// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"encoding/hex"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const katSeed = "lux-pedersen-kat-v1"

// katCases is the canonical KAT table for Pedersen commitments over BN254
// with generators derived from DeterministicGenerators(katSeed).
//
// Format: m, r (uint64) -> hex of commit.RawBytes() (64 bytes uncompressed
// affine: x || y, big-endian).
//
// Generated once via /tmp/pdgen.go; any deviation in the byte-equal output
// of either Commit or DeterministicGenerators breaks this test loudly.
var katCases = []struct {
	m, r uint64
	hex  string
}{
	{0x0, 0x0, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
	{0x1, 0x0, "2310d50ca3158e269dc37815614edd42375c9a6f9c74f91a6378d8090c74e98c2783703587b324f031f528caef154a1612cbcd8a5e56e4b9e48b0fc235a249ad"},
	{0x0, 0x1, "1832d62bfd4f05533bac846e2e899b78b5dd985a3f80438adab0b5d7ef77ab420d2263bda11d9cb874eb5afce16bb6a3d5d9685a0da11c6e2fcf76dd9aba361a"},
	{0x1, 0x1, "09444d23ca0c39d550f69b46291c04ed8acbe83f9538497df61b4abc5b83650d26b590b491bac2b0c7d7e7504dcaa9cb9747492de57178ec77cfe7a1ab4d58e0"},
	{0x7, 0xd, "041a9769b433550c22ae82929c2c6e97bc384f58527d1e04257879e9bd43f3dd1cf90b789b4ea6b8720b5190df8770b6a058bfe47abcfc4ff81baf8a94d2ed73"},
	{0x5, 0xb, "09d0f5e13cec7feef92fb061025e4d1b04516bc97a33c079c3b35958e905d56b01282228cdc98d0a7f4ba3e20de6d021fa2a6e3aa3e7e2ad1cfb9081e9eb0149"},
	{0xdeadbeef, 0xcafebabe, "0e5218d479935a1122d73ca4da24913fa2902c16ec8f0b41520945054945e409055967e503083e0ef918cfc5a16d91138b526f97df01b7bb1aeaf9fc2b39bcc9"},
	{0x1, 0xffffffffffffffff, "0a4eda06d99f3fccbf4b0b22326abe9ba08ee4de5d102275353e3a7101712c8e1aff88e50bb4ea4a5d24789df8bc803d8d202c0bcdd6e59ccf9c6f33bf7b69dd"},
	{0xffffffffffffffff, 0x1, "297f6e6ae77d1636e06508bc4443544d411faab1d6bc5801498dea30047192101bdc0e255c38b1a96e8d668d5f6d6620bab6c5c2134cd505771f80198eaf35c9"},
	{0x2a, 0x6c1, "08ffa127da11795588ec290e2fc944902bf86f11078abf16a63a7e786b38f1aa1667ff1bcbd1bffdd6d3e6836986ff84b213d705e97a47ae0d3d94a245f98224"},
	{0x499602d2, 0x24cb016ea, "0c8c93752e15f732ad39af50dbfb0a6983da1d4bf0a4cf62181acb9b5980b05b237dc1d486d64d7cd42f02c320d6d08d5787f7925cb59358e39c8aad8b282287"},
}

func TestKATs(t *testing.T) {
	gens, err := DeterministicGenerators([]byte(katSeed))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range katCases {
		var m, r fr.Element
		m.SetUint64(tc.m)
		r.SetUint64(tc.r)
		c := gens.Commit(&m, &r)
		raw := c.RawBytes()
		got := hex.EncodeToString(raw[:])
		if got != tc.hex {
			t.Errorf("Commit(m=0x%x, r=0x%x): got %s want %s", tc.m, tc.r, got, tc.hex)
		}
	}
}

func TestCommitmentHomomorphism(t *testing.T) {
	gens, err := NewGenerators(nil)
	if err != nil {
		t.Fatal(err)
	}
	var m1, r1, m2, r2 fr.Element
	m1.SetUint64(7)
	r1.SetUint64(13)
	m2.SetUint64(5)
	r2.SetUint64(11)

	c1 := gens.Commit(&m1, &r1)
	c2 := gens.Commit(&m2, &r2)

	// Commit(m1+m2, r1+r2) should equal c1 + c2.
	var mSum, rSum fr.Element
	mSum.Add(&m1, &m2)
	rSum.Add(&r1, &r2)
	cSum := gens.Commit(&mSum, &rSum)

	var aJ, bJ bn254.G1Jac
	aJ.FromAffine(&c1)
	bJ.FromAffine(&c2)
	aJ.AddAssign(&bJ)
	var got bn254.G1Affine
	got.FromJacobian(&aJ)

	if !got.Equal(&cSum) {
		t.Errorf("Pedersen homomorphism violated:\ngot=%v\nwant=%v", got, cSum)
	}
}

func TestNewGeneratorsIndependent(t *testing.T) {
	gens, err := NewGenerators(nil)
	if err != nil {
		t.Fatal(err)
	}
	var gAff, hAff bn254.G1Affine
	gAff.FromJacobian(&gens.G)
	hAff.FromJacobian(&gens.H)
	if gAff.Equal(&hAff) {
		t.Error("G and H must be independent")
	}
}

func TestCommitBatch(t *testing.T) {
	gens, err := DeterministicGenerators([]byte(katSeed))
	if err != nil {
		t.Fatal(err)
	}
	ms := make([]fr.Element, len(katCases))
	rs := make([]fr.Element, len(katCases))
	for i, tc := range katCases {
		ms[i].SetUint64(tc.m)
		rs[i].SetUint64(tc.r)
	}
	got, err := gens.CommitBatch(ms, rs)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range katCases {
		raw := got[i].RawBytes()
		if hex.EncodeToString(raw[:]) != tc.hex {
			t.Errorf("CommitBatch[%d]: mismatch", i)
		}
	}
}

func TestCommitBatchLengthMismatch(t *testing.T) {
	gens, err := NewGenerators(nil)
	if err != nil {
		t.Fatal(err)
	}
	ms := make([]fr.Element, 3)
	rs := make([]fr.Element, 4)
	if _, err := gens.CommitBatch(ms, rs); err != ErrLength {
		t.Errorf("expected ErrLength, got %v", err)
	}
}
