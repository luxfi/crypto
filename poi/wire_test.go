package poi

import (
	"bytes"
	"testing"
)

func sampleOpening() (root [32]byte, beacon []byte, op Opening) {
	s := uint64(0xC0DE)
	tr := NewTranscript()
	tr.Matmul(randMat(2, 3, &s), randMat(3, 2, &s))
	tr.Matmul(randMat(4, 8, &s), randMat(8, 5, &s))
	tr.Matmul(randMat(2, 2, &s), randMat(2, 2, &s))
	root = tr.Root()
	beacon = []byte("beacon:wire")
	op = tr.Open(ChallengeIndex(beacon, root, tr.Len()))
	return
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	root, beacon, op := sampleOpening()
	enc := EncodeOpening(root, beacon, op)
	gotRoot, gotBeacon, gotOp, err := DecodeOpening(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotRoot != root || !bytes.Equal(gotBeacon, beacon) || gotOp.Index != op.Index {
		t.Fatal("round-trip header mismatch")
	}
	if gotOp.A.Rows != op.A.Rows || gotOp.B.Cols != op.B.Cols || gotOp.C.Rows != op.C.Rows {
		t.Fatal("round-trip matrix shape mismatch")
	}
	for i := range op.C.Data {
		if gotOp.C.Data[i] != op.C.Data[i] {
			t.Fatalf("round-trip C[%d] mismatch", i)
		}
	}
	if len(gotOp.Proof) != len(op.Proof) {
		t.Fatal("round-trip proof length mismatch")
	}
}

// CheckOpening is the precompile payload: honest opening → included && freivaldsOK.
func TestCheckOpening_Honest(t *testing.T) {
	root, beacon, op := sampleOpening()
	enc := EncodeOpening(root, beacon, op)
	included, ok, err := CheckOpening(enc, 2)
	if err != nil || !included || !ok {
		t.Fatalf("honest opening: included=%v ok=%v err=%v (want true,true,nil)", included, ok, err)
	}
}

// A fabricated output: included (committed) but Freivalds fails → the precompile reports fraud.
func TestCheckOpening_Fraud(t *testing.T) {
	s := uint64(0xF00D)
	tr := NewTranscript()
	a := randMat(3, 5, &s)
	b := randMat(5, 4, &s)
	fake := ExactMatmul(a, b)
	fake.Data[7]++
	tr.CommitClaimed(a, b, fake)
	enc := EncodeOpening(tr.Root(), []byte("beacon:fraud"), tr.Open(0))
	included, ok, err := CheckOpening(enc, 2)
	if err != nil || !included || ok {
		t.Fatalf("fraud opening: included=%v ok=%v err=%v (want true,false,nil)", included, ok, err)
	}
}

// A made-up opening not committed under the root → not included (a griefer cannot fake a slash).
func TestCheckOpening_NotIncluded(t *testing.T) {
	s := uint64(0x9999)
	a := randMat(2, 2, &s)
	b := randMat(2, 2, &s)
	c := ExactMatmul(a, b)
	var bogusRoot [32]byte
	bogusRoot[0] = 0xAB
	enc := EncodeOpening(bogusRoot, []byte("beacon:grief"), Opening{Index: 0, A: a, B: b, C: c, Proof: nil})
	included, _, err := CheckOpening(enc, 2)
	if err != nil || included {
		t.Fatalf("uncommitted opening: included=%v err=%v (want false,nil)", included, err)
	}
}

func TestDecodeOpening_Truncated(t *testing.T) {
	root, beacon, op := sampleOpening()
	enc := EncodeOpening(root, beacon, op)
	if _, _, _, err := DecodeOpening(enc[:len(enc)-4]); err == nil {
		t.Fatal("truncated frame must error, not panic")
	}
	if _, _, _, err := DecodeOpening(enc[:10]); err == nil {
		t.Fatal("tiny frame must error")
	}
}
