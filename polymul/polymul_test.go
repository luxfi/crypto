package polymul

import "testing"

func TestMulNegacyclicBasic(t *testing.T) {
	// (1 + X) * (1 + X) mod (X^4 + 1) = 1 + 2X + X^2.
	a := []uint64{1, 1, 0, 0}
	b := []uint64{1, 1, 0, 0}
	c, err := MulNegacyclic(a, b, 17)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint64{1, 2, 1, 0}
	for i, v := range want {
		if c[i] != v {
			t.Errorf("c[%d] = %d; want %d", i, c[i], v)
		}
	}
}

func TestMulNegacyclicWrap(t *testing.T) {
	// X^3 * X mod (X^4 + 1) = -1 = q-1.
	a := []uint64{0, 0, 0, 1}
	b := []uint64{0, 1, 0, 0}
	c, err := MulNegacyclic(a, b, 17)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint64{16, 0, 0, 0}
	for i, v := range want {
		if c[i] != v {
			t.Errorf("c[%d] = %d; want %d", i, c[i], v)
		}
	}
}

func TestMulNegacyclicLengthMismatch(t *testing.T) {
	_, err := MulNegacyclic([]uint64{1, 2}, []uint64{1, 2, 3}, 17)
	if err != ErrLengthMismatch {
		t.Errorf("got %v want %v", err, ErrLengthMismatch)
	}
}
