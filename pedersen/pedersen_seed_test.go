// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"encoding/hex"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func affineHex(p *bn254.G1Affine) string {
	b := p.Bytes() // gnark-crypto compressed form: 32 bytes (X with Y-parity flags)
	return hex.EncodeToString(b[:])
}

func toAffine(g *Generators) (bn254.G1Affine, bn254.G1Affine) {
	var gA, hA bn254.G1Affine
	gA.FromJacobian(&g.G)
	hA.FromJacobian(&g.H)
	return gA, hA
}

// TestNewGeneratorsFromSeed_Deterministic: same seed → same generators.
func TestNewGeneratorsFromSeed_Deterministic(t *testing.T) {
	cases := [][32]byte{
		zeroSeed(),
		oneSeed(),
		incrementingSeed(),
		highBitSeed(),
		mixedSeed(),
	}
	for i, seed := range cases {
		a, err := NewGeneratorsFromSeed(seed)
		if err != nil {
			t.Fatalf("case %d: a: %v", i, err)
		}
		b, err := NewGeneratorsFromSeed(seed)
		if err != nil {
			t.Fatalf("case %d: b: %v", i, err)
		}
		ag, ah := toAffine(a)
		bg, bh := toAffine(b)
		if !ag.Equal(&bg) || !ah.Equal(&bh) {
			t.Fatalf("case %d: non-deterministic output for identical seed", i)
		}
		if !ag.IsInSubGroup() || !ah.IsInSubGroup() {
			t.Fatalf("case %d: derived generator not in prime-order subgroup", i)
		}
		if ag.Equal(&ah) {
			t.Fatalf("case %d: G and H must be independent", i)
		}
	}
}

// TestNewGeneratorsFromSeed_DistinctSeeds: different seeds → different generators.
func TestNewGeneratorsFromSeed_DistinctSeeds(t *testing.T) {
	pairs := [][2][32]byte{
		{zeroSeed(), oneSeed()},
		{zeroSeed(), incrementingSeed()},
		{oneSeed(), highBitSeed()},
		{incrementingSeed(), mixedSeed()},
		{highBitSeed(), mixedSeed()},
	}
	for i, p := range pairs {
		a, err := NewGeneratorsFromSeed(p[0])
		if err != nil {
			t.Fatalf("case %d: a: %v", i, err)
		}
		b, err := NewGeneratorsFromSeed(p[1])
		if err != nil {
			t.Fatalf("case %d: b: %v", i, err)
		}
		ag, ah := toAffine(a)
		bg, bh := toAffine(b)
		if ag.Equal(&bg) {
			t.Fatalf("case %d: distinct seeds produced identical G", i)
		}
		if ah.Equal(&bh) {
			t.Fatalf("case %d: distinct seeds produced identical H", i)
		}
	}
}

// TestNewGeneratorsFromSeed_CommitsHomomorphic: derived basis still satisfies
// the Pedersen homomorphism: Commit(m1+m2, r1+r2) == Commit(m1, r1) + Commit(m2, r2).
func TestNewGeneratorsFromSeed_CommitsHomomorphic(t *testing.T) {
	gens, err := NewGeneratorsFromSeed(incrementingSeed())
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
		t.Fatalf("homomorphism violated for seeded generators")
	}
}

// TestNewGeneratorsFromSeed_GoldenVector freezes a hard-coded expected output
// for seed = {0,1,...,31}. Any future change to the derivation algorithm will
// trip this test, forcing a coordinated update to the C++/Rust KAT generators.
//
// Encoding: gnark-crypto bn254.G1Affine.Bytes() is 32 bytes, compressed
// big-endian (X coord with Y-parity in top bits, per the gnark-crypto
// internal compressed form).
func TestNewGeneratorsFromSeed_GoldenVector(t *testing.T) {
	gens, err := NewGeneratorsFromSeed(incrementingSeed())
	if err != nil {
		t.Fatal(err)
	}
	gA, hA := toAffine(gens)
	gotG := affineHex(&gA)
	gotH := affineHex(&hA)

	const wantG = "c563aa8a283f268b65b4210a0a78ee1341f76b59d94c1ac626effe1a5aa0c6b7"
	const wantH = "e9ebf4392683dcb418584dd8ecd1e1dd16b486147e676dbf4b62779a340f3186"

	if gotG != wantG {
		t.Fatalf("golden G mismatch (derivation regression):\n got=%s\nwant=%s", gotG, wantG)
	}
	if gotH != wantH {
		t.Fatalf("golden H mismatch (derivation regression):\n got=%s\nwant=%s", gotH, wantH)
	}
}

// --- helpers ---

func zeroSeed() [32]byte {
	var s [32]byte
	return s
}

func oneSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = 1
	}
	return s
}

func incrementingSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func highBitSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = 0x80
	}
	return s
}

func mixedSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(0xA5 ^ i)
	}
	return s
}
