// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"crypto/sha256"
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
// Generators use the canonical SeededGenDST = "PEDERSEN_SEEDED_GEN_V1" with
// counter encoding key||u64_le(0) for G and key||u64_le(1) for H, where
// key = SHA-256(katSeed). This matches the C++/Metal/CUDA/WGSL canonical
// (luxcpp/crypto/pedersen — DST_SEEDED_GEN). Any deviation in the byte-equal
// output of Commit or DeterministicGenerators breaks this test loudly.
//
// Vectors regenerated 2026-05-01 after collapsing the legacy two-DST
// PEDERSEN_G_V1 / PEDERSEN_H_V1 path (LP-137 RED-FINAL §2.4 / N3).
var katCases = []struct {
	m, r uint64
	hex  string
}{
	{0x0, 0x0, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
	{0x1, 0x0, "1c3bd8ba19f64625f7c4e5e5a9a23f6669a50df47939a9b8ecf195816c0c321b2f62c0a6f193e6e5caeedcf6020522e20133dee692b17a24b30fda2d8844dd00"},
	{0x0, 0x1, "1ae5ba2da9c3815b91a40f72dfdc3b7cf4e0ecf26c0edfcd9cd139703e9d8b9e2d40ef5624a87fcaaa0f522d16e50bdfeb3bd43ef2c1e3fc7feb2587ef80e059"},
	{0x1, 0x1, "1949c5277a73c11d89e6d87b351091be4af586b4433af6bb6c65daa285fd13841c8e1f5677b3002a6f60e2e4b476e0bdde9fe14d4231f1d2d76398e3e0f860dd"},
	{0x7, 0xd, "2797ede04358c04ed45a0d8cf8b466a7500a7c4270f00a54039e5edd92c13dd5041be4807242fb18242a3cea05530959dd7cd79f431848e0e766dcae06ed9b35"},
	{0x5, 0xb, "2a9c798a92bd8201c99222ea4239acd9ac1c137ea5bace9628ecaf45892b7ef510f58c836a50953a4cafb885952c735c57ae1bb0c4a7c17fee0d6831870405c9"},
	{0xdeadbeef, 0xcafebabe, "0a8297e7e4f1dd95342e86063093b3d2def5154c4e64ccd64cff91578c3b367b11569aa1796992eaf45b19fee627ec75487e40f96c172b769c4e3dd58f4ab85f"},
	{0x1, 0xffffffffffffffff, "1bce42ec6446cfb0d7ef1ba7a8ff7c1933abc562a2643cab919a8c679de26b7c0011efe3d15f08817f22198b048cb56820adb48c15dd8e613bc94eba86942544"},
	{0xffffffffffffffff, 0x1, "02193d1fe951c032cae5f04d7e820842345447e0d19d72c1eb5c05dd13b47a401c4499ff58c3c405e764a9960e23e68d16a46c14e94c03c99328918c54308f76"},
	{0x2a, 0x6c1, "26a58f8326223a7bef10fb8e1bfffdf9092d610a7c66a277c64b3c74cf45e755151f04cb717b138740cbfdc97ce54dde1733b3716ff2604a5d96cf296609d228"},
	{0x499602d2, 0x24cb016ea, "0f708ac592493a8e371e0f3d523916bc0e9fb00002cfb6c40f1553ae1919d14521ce35965d7f912efa4059c44cdf6c4858e175731bd30da550c52746f2935a71"},
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

// TestCanonicalSeededDST locks the on-wire DST string. The C++ canonical at
// luxcpp/crypto/pedersen/cpp/pedersen.hpp uses the same constant; any drift
// here breaks GPU↔CPU byte-equality and re-opens LP-137 RED-FINAL N3.
func TestCanonicalSeededDST(t *testing.T) {
	if SeededGenDST != "PEDERSEN_SEEDED_GEN_V1" {
		t.Fatalf("SeededGenDST drift: got %q want %q", SeededGenDST, "PEDERSEN_SEEDED_GEN_V1")
	}
}

// TestDeterministicMatchesFromSeed verifies that DeterministicGenerators
// (arbitrary-length seed) reduces to NewGeneratorsFromSeed(SHA-256(seed)),
// which is the contract the post-N3 collapse promises.
func TestDeterministicMatchesFromSeed(t *testing.T) {
	a, err := DeterministicGenerators([]byte(katSeed))
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(katSeed))
	b, err := NewGeneratorsFromSeed(key)
	if err != nil {
		t.Fatal(err)
	}
	var ag, bg, ah, bh bn254.G1Affine
	ag.FromJacobian(&a.G)
	bg.FromJacobian(&b.G)
	ah.FromJacobian(&a.H)
	bh.FromJacobian(&b.H)
	if !ag.Equal(&bg) || !ah.Equal(&bh) {
		t.Fatalf("DeterministicGenerators must equal NewGeneratorsFromSeed(SHA-256(seed))")
	}
}
