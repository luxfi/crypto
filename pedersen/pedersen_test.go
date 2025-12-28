package pedersen

import (
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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
