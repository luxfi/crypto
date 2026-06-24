package poi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// a tiny deterministic generator so the Go and Rust tests build identical int8-ish matrices.
func lcg(s *uint64) int64 {
	*s = *s*6364136223846793005 + 1442695040888963407
	return int64((*s>>33)%127) - 63
}

func randMat(rows, cols int, s *uint64) Mat {
	d := make([]int64, rows*cols)
	for i := range d {
		d[i] = lcg(s)
	}
	return NewMat(rows, cols, d)
}

func TestExactMatmul(t *testing.T) {
	a := NewMat(2, 2, []int64{1, 2, 3, 4})
	b := NewMat(2, 2, []int64{5, 6, 7, 8})
	c := ExactMatmul(a, b) // [[19,22],[43,50]]
	want := []int64{19, 22, 43, 50}
	for i := range want {
		if c.Data[i] != want[i] {
			t.Fatalf("ExactMatmul[%d]=%d want %d", i, c.Data[i], want[i])
		}
	}
}

// The headline property: an honest forward pass answers a beacon-selected matmul challenge, and a
// fabricated output is CAUGHT — VerifyOpening is the production caller of Verify.
func TestHonestOpeningVerifies(t *testing.T) {
	s := uint64(0xA1CE)
	tr := NewTranscript()
	acts := randMat(4, 64, &s)
	w1 := randMat(64, 48, &s)
	h := tr.Matmul(acts, w1)
	tr.Matmul(h, randMat(48, 32, &s))
	tr.Matmul(randMat(4, 32, &s), randMat(32, 16, &s))

	root := tr.Root()
	beacon := []byte("beacon:block-9001")
	idx := ChallengeIndex(beacon, root, tr.Len())
	op := tr.Open(idx)
	if !VerifyOpening(root, beacon, op, 2) {
		t.Fatal("honest forward pass must pass the opened-matmul challenge")
	}
	// every matmul, whichever the beacon picks, must verify
	for i := 0; i < tr.Len(); i++ {
		if !VerifyOpening(root, beacon, tr.Open(i), 2) {
			t.Fatalf("honest matmul %d must verify", i)
		}
	}
}

func TestFabricatedOutputCaught(t *testing.T) {
	s := uint64(0xF00D)
	tr := NewTranscript()
	a := randMat(4, 64, &s)
	b := randMat(64, 32, &s)
	fake := ExactMatmul(a, b)
	fake.Data[5]++ // a single output entry never produced by A·B
	tr.CommitClaimed(a, b, fake)
	if VerifyOpening(tr.Root(), []byte("beacon:catch"), tr.Open(0), 2) {
		t.Fatal("a fabricated output (C != A*B) must be CAUGHT")
	}
}

func TestSwappedRevealCaught(t *testing.T) {
	s := uint64(0x5151)
	tr := NewTranscript()
	a := randMat(4, 48, &s)
	b := randMat(48, 24, &s)
	bad := ExactMatmul(a, b)
	bad.Data[3] -= 2
	tr.CommitClaimed(a, b, bad) // committed over a wrong C
	good := ExactMatmul(a, b)
	op := Opening{Index: 0, A: a, B: b, C: good, Proof: MerkleProof(tr.leaves, 0)}
	if VerifyOpening(tr.Root(), []byte("beacon:swap"), op, 2) {
		t.Fatal("revealing operands never committed must fail Merkle inclusion")
	}
}

func TestMerkleInclusionIndexFold(t *testing.T) {
	leaves := make([][32]byte, 3)
	for i := range leaves {
		leaves[i] = MatmulLeaf(NewMat(1, 1, []int64{int64(i)}), NewMat(1, 1, []int64{1}), NewMat(1, 1, []int64{int64(i)}))
	}
	root := MerkleRoot(leaves)
	for i, leaf := range leaves {
		if !MerkleVerify(leaf, root, i, MerkleProof(leaves, i)) {
			t.Fatalf("leaf %d must verify", i)
		}
	}
}

// CROSS-LANGUAGE PARITY: this exact (seed,n,k) and its first values are pinned identically in the
// Rust test (hanzo-engine/src/poi.rs::test_derive_challenges_keccak_golden). If either side's
// keccak/encoding drifts, one of the two test suites breaks — the parity is enforced, not assumed.
func TestDeriveChallengesGolden(t *testing.T) {
	seed := []byte("poi-parity-seed")
	ch := DeriveChallenges(seed, 4, 2)
	if len(ch) != 2 || len(ch[0]) != 4 {
		t.Fatalf("shape: got %dx%d", len(ch), len(ch[0]))
	}
	// emit the golden so it can be pinned in Rust; assert the structural invariants here.
	for j := range ch {
		for i := range ch[j] {
			if ch[j][i] >= P {
				t.Fatalf("challenge ch[%d][%d]=%d not reduced mod P", j, i, ch[j][i])
			}
		}
	}
	// pinned values (computed by this canonical Go keccak path; Rust must match byte-for-byte)
	wantHex := goldenHex(ch)
	if wantHex != poiGoldenParity {
		t.Fatalf("golden derive-challenges drifted:\n got %s\n want %s", wantHex, poiGoldenParity)
	}
}

// goldenHex serializes the challenge matrix as big-endian u64s for a stable cross-language pin.
func goldenHex(ch [][]uint64) string {
	var b bytes.Buffer
	for _, row := range ch {
		for _, v := range row {
			var u [8]byte
			for k := 0; k < 8; k++ {
				u[7-k] = byte(v >> (8 * k))
			}
			b.Write(u[:])
		}
	}
	return hex.EncodeToString(b.Bytes())
}

// poiGoldenParity is the canonical DeriveChallenges([]byte("poi-parity-seed"),4,2) value. It is
// recomputed and asserted on every run (TestDeriveChallengesGolden) and mirrored in Rust.
const poiGoldenParity = "1b3c3bb2aa818c7e0b75620eafd2e35206f000322286987412a71a33da4219920934404c5bc1635a1b934a274b2eaa4801b82451d55b616d142238c54b6a7d51"
