package poseidon

import "testing"

func TestSum2Deterministic(t *testing.T) {
	in := make([]byte, 64)
	for i := range in {
		in[i] = byte(i)
	}
	a, err := Sum2(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sum2(in)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("Sum2 not deterministic: %x vs %x", a, b)
	}
}

func TestSum2RejectsNon32(t *testing.T) {
	_, err := Sum2([]byte{1, 2, 3})
	if err != ErrInvalidFieldSize {
		t.Errorf("expected ErrInvalidFieldSize; got %v", err)
	}
}

func TestSum2DistinctInputs(t *testing.T) {
	in1 := make([]byte, 32)
	in2 := make([]byte, 32)
	in2[0] = 1
	a, _ := Sum2(in1)
	b, _ := Sum2(in2)
	if a == b {
		t.Errorf("distinct inputs collide: %x", a)
	}
}
