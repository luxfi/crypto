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
// Generators use the canonical brand-neutral DSTs PEDERSEN_G_V1 and
// PEDERSEN_H_V1 (matches C++/Metal/CUDA/WGSL canonical). Any deviation in
// the byte-equal output of either Commit or DeterministicGenerators breaks
// this test loudly.
var katCases = []struct {
	m, r uint64
	hex  string
}{
	{0x0, 0x0, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
	{0x1, 0x0, "1690bf214b3b458ac68ff8ad15298b2c0757eb3c908bd196d20a1a28032749bd2142beee737e4802be84e65551e57ad829fc3084a712503e38c09a171b8f7af8"},
	{0x0, 0x1, "11ed080cfc66661d0256d269e66fba661924d0e95c02763b6a9c3c848f8eb40c07682429c46304a6f09495a4036e794669f91858d53ac89c06b0db6bbebf8907"},
	{0x1, 0x1, "046bf2f0fd48f5378636781d86b78ba9dfecdbc6fedaa15feb0caf59cd10f65e07db066137fec1f80c8eff58e6968dec57149f293b7e8e15ebfee303b5d9dabf"},
	{0x7, 0xd, "1fd7362ee9fdb2fe14708eaeb359cf0790e05011ea0f75eff0950982b0fb1bbe07a6a565ea9db0073d3d057d4f643c985de3acf1639853e7800347979e35f95e"},
	{0x5, 0xb, "227f1cbf8905b2b56628a794770047335d1902ce2a1015deb9727099570a067923ccb9407067a34a178926e5627addf4262cf5c235902b78acf0b2119f8a3bff"},
	{0xdeadbeef, 0xcafebabe, "2151496276fae67477633528c8e1b29b144526713297da2fb6b58f64afb24295162abca28ca2d2055910e3d852b5edb3611055bccca66b3b7f372e2d25312f8d"},
	{0x1, 0xffffffffffffffff, "2cb8a0a4f69fdabbf027456efa83963005a1b5347069bb5a6832ae8473ca39341a898c5bb4842c504b3d6030e5593566af58088bdb950de9d78db1096df220e2"},
	{0xffffffffffffffff, 0x1, "2bf9365670f2dc77b54c01178714048abdd75cb6c5bd77b8a1180e28964cf8cd044540b44128e0bb43a73e68fb29bee84f8e7ff1324bd551181c1e8a4a8d3da5"},
	{0x2a, 0x6c1, "146d5342e3acc1ce2a6b83d879a876c063a0a2ad8ce0d3c27efd624c9f33accb05b8c5f8e773ee4d7082ad7c103c639abcae61327d57cdb9d0d1f4acb0eeb566"},
	{0x499602d2, 0x24cb016ea, "12778b903c6ce3846d58ffbeee0e173ba26b6ac95c8987001e6fa9a37f114e2f2a5c6eef88c60deb4d89bb11fdd769dafd0b0a19e2e6bc647f620bcc2bdaf92a"},
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
