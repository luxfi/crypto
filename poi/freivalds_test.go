package poi

import "testing"

// fixture: A=[[1,2],[3,4]], B=[[5,6],[7,8]], C = A·B = [[19,22],[43,50]].
func fixture() (Mat, Mat, Mat) {
	a := NewMat(2, 2, []int64{1, 2, 3, 4})
	b := NewMat(2, 2, []int64{5, 6, 7, 8})
	c := NewMat(2, 2, []int64{19, 22, 43, 50})
	return a, b, c
}

func TestHonestMatmulPasses(t *testing.T) {
	a, b, c := fixture()
	ch := DeriveChallenges([]byte("beluga"), 2, 4)
	if !VerifyMulti(a, b, c, ch) {
		t.Fatal("honest C = A·B must pass every challenge")
	}
}

func TestTamperedOutputIsCaught(t *testing.T) {
	a, b, _ := fixture()
	cBad := NewMat(2, 2, []int64{19, 22, 43, 51}) // 50 -> 51: a faker who never multiplied
	ch := DeriveChallenges([]byte("beluga"), 2, 4)
	if VerifyMulti(a, b, cBad, ch) {
		t.Fatal("a single tampered output entry must be CAUGHT (Freivalds soundness)")
	}
}

func TestNegativeEntriesFieldReduction(t *testing.T) {
	// int8 activations/weights are signed; toField must handle negatives exactly.
	a := NewMat(2, 2, []int64{1, -2, 3, 4})
	b := NewMat(2, 2, []int64{5, 6, -7, 8})
	c := NewMat(2, 2, []int64{19, -10, -13, 50}) // exact A·B
	ch := DeriveChallenges([]byte{7}, 2, 4)
	if !VerifyMulti(a, b, c, ch) {
		t.Fatal("honest matmul with negatives passes")
	}
	cBad := NewMat(2, 2, []int64{19, -10, -13, 49})
	if VerifyMulti(a, b, cBad, ch) {
		t.Fatal("tampered negative-entry matmul caught")
	}
}

func TestChallengeDerivationDeterministic(t *testing.T) {
	if !chEq(DeriveChallenges([]byte("x"), 8, 3), DeriveChallenges([]byte("x"), 8, 3)) {
		t.Fatal("prover and verifier must derive identical challenges from the same seed")
	}
	if chEq(DeriveChallenges([]byte("x"), 8, 3), DeriveChallenges([]byte("y"), 8, 3)) {
		t.Fatal("different seeds must give different challenges")
	}
}

func TestWrongDimsRejected(t *testing.T) {
	a := NewMat(2, 3, []int64{1, 2, 3, 4, 5, 6})
	b := NewMat(2, 2, []int64{1, 2, 3, 4}) // b.Rows(2) != a.Cols(3)
	c := NewMat(2, 2, []int64{1, 2, 3, 4})
	if Verify(a, b, c, []uint64{1, 1}) {
		t.Fatal("shape mismatch must fail closed")
	}
}

func TestLargerRandomMatmulCatchesSparseCheat(t *testing.T) {
	// 16x24 · 24x16: compute C exactly, then flip a single deep entry — the sparse-cheat case.
	const tt, kk, nn = 16, 24, 16
	var sa, sb uint64 = 0x12345678, 0x9abcdef0
	rnd := func(s *uint64) int64 {
		*s = (*s)*6364136223846793005 + 1442695040888963407
		return int64((*s>>33)%127) - 63
	}
	aData := make([]int64, tt*kk)
	for i := range aData {
		aData[i] = rnd(&sa)
	}
	bData := make([]int64, kk*nn)
	for i := range bData {
		bData[i] = rnd(&sb)
	}
	a := NewMat(tt, kk, aData)
	b := NewMat(kk, nn, bData)
	cData := make([]int64, tt*nn)
	for i := 0; i < tt; i++ {
		for j := 0; j < nn; j++ {
			var acc int64
			for x := 0; x < kk; x++ {
				acc += aData[i*kk+x] * bData[x*nn+j]
			}
			cData[i*nn+j] = acc
		}
	}
	c := NewMat(tt, nn, append([]int64(nil), cData...))
	ch := DeriveChallenges([]byte("coffee"), nn, 2)
	if !VerifyMulti(a, b, c, ch) {
		t.Fatal("honest large matmul passes")
	}
	bad := append([]int64(nil), cData...)
	bad[7*nn+11]++ // one entry off by one
	cBad := NewMat(tt, nn, bad)
	if VerifyMulti(a, b, cBad, ch) {
		t.Fatal("off-by-one in one buried entry is caught")
	}
}

func chEq(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalU64(a[i], b[i]) {
			return false
		}
	}
	return true
}
