package ntt

import "testing"

// Use a tiny prime (97) where 28 is a primitive 8th root of unity:
// 28^8 mod 97 = 1; for k = 1..7, 28^k mod 97 != 1.
const (
	q     = uint64(97)
	omega = uint64(28)
)

func TestNTTRoundTrip(t *testing.T) {
	want := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	a := append([]uint64(nil), want...)
	if err := NTT(a, omega, q); err != nil {
		t.Fatal(err)
	}
	// Output is bit-reversed but transformed; we don't compare against
	// hand-computed values here (that's brittle). Instead invert and check
	// we get back the original.
	omegaInv := powMod(omega, q-2, q) // Fermat
	nInv := powMod(uint64(len(a)), q-2, q)
	if err := INTT(a, omegaInv, nInv, q); err != nil {
		t.Fatal(err)
	}
	for i, v := range a {
		if v != want[i] {
			t.Errorf("round trip[%d] = %d; want %d", i, v, want[i])
		}
	}
}

func TestNTTRejectsBadInputs(t *testing.T) {
	if err := NTT([]uint64{1, 2, 3}, omega, q); err != ErrNotPow2 {
		t.Errorf("non-pow2: got %v want %v", err, ErrNotPow2)
	}
	if err := NTT([]uint64{1, 2}, omega, 0); err != ErrModulusZero {
		t.Errorf("modulus 0: got %v want %v", err, ErrModulusZero)
	}
}

func TestNTTLinearity(t *testing.T) {
	// NTT(a + b) should equal NTT(a) + NTT(b) componentwise mod q.
	a := []uint64{1, 0, 0, 0, 0, 0, 0, 0}
	b := []uint64{0, 1, 0, 0, 0, 0, 0, 0}
	sum := make([]uint64, 8)
	for i := range sum {
		sum[i] = (a[i] + b[i]) % q
	}

	A := append([]uint64(nil), a...)
	B := append([]uint64(nil), b...)
	S := append([]uint64(nil), sum...)
	if err := NTT(A, omega, q); err != nil {
		t.Fatal(err)
	}
	if err := NTT(B, omega, q); err != nil {
		t.Fatal(err)
	}
	if err := NTT(S, omega, q); err != nil {
		t.Fatal(err)
	}
	for i := range S {
		if want := (A[i] + B[i]) % q; want != S[i] {
			t.Errorf("linearity fail at %d: got %d want %d", i, S[i], want)
		}
	}
}
