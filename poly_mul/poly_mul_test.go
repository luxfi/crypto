// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.

package poly_mul

import (
	"testing"
)

// lcg generates a deterministic test vector. Same LCG used by the C++ port
// and the Metal kernel test to keep KAT inputs byte-equal across all layers.
func lcg(seed uint64, n int) []uint64 {
	out := make([]uint64, n)
	state := seed
	for i := range out {
		state = state*6364136223846793005 + 1442695040888963407
		out[i] = state % Q
	}
	return out
}

// TestKATs is the canonical Known-Answer Test vector for poly_mul.
// 10 cases spanning n=2..1024. Computed once via the schoolbook reference
// and embedded as constants so any code change that breaks compatibility
// fails immediately and visibly.
//
// The (n, seedA, seedB, sum, first, last) tuple is the byte-equal contract
// that C++ and Metal layers MUST match.
func TestKATs(t *testing.T) {
	type kat struct {
		name             string
		n                int
		sA, sB           uint64
		sum, first, last uint64
	}
	kats := []kat{
		{"n2", 2, 0x1, 0x2, 567996115, 371012399, 196983716},
		{"n4", 4, 0x64, 0xc8, 935898137, 410827071, 376044324},
		{"n8", 8, 0x4d2, 0x162e, 48246169, 673146415, 767542882},
		{"n16", 16, 0xdeadbeef, 0xcafebabe, 590901354, 41636199, 860993788},
		{"n32", 32, 0x7, 0xd, 72828809, 392054258, 84461645},
		{"n64", 64, 0xb, 0x11, 933631914, 967956798, 522099145},
		{"n128", 128, 0x13, 0x17, 443591268, 429303763, 461383520},
		{"n256", 256, 0x1, 0x2, 78388485, 359306289, 229818328},
		{"n512", 512, 0x1f, 0x25, 723079964, 641254315, 816782592},
		{"n1024", 1024, 0x29, 0x2b, 308246040, 8552215, 931224377},
	}

	for _, tc := range kats {
		t.Run(tc.name, func(t *testing.T) {
			a := lcg(tc.sA, tc.n)
			b := lcg(tc.sB, tc.n)

			// Schoolbook (always)
			cs, err := MulSchoolbook(a, b)
			if err != nil {
				t.Fatalf("MulSchoolbook: %v", err)
			}
			checkKAT(t, "schoolbook", cs, tc.sum, tc.first, tc.last)

			// NTT path (where supported)
			if tc.n >= 2 && tc.n&(tc.n-1) == 0 && tc.n <= (1<<MaxLogN)/2 {
				cn, err := MulNTT(a, b)
				if err != nil {
					t.Fatalf("MulNTT: %v", err)
				}
				checkKAT(t, "ntt", cn, tc.sum, tc.first, tc.last)
				// schoolbook == NTT byte-for-byte
				if len(cs) != len(cn) {
					t.Fatalf("length mismatch")
				}
				for i := range cs {
					if cs[i] != cn[i] {
						t.Fatalf("schoolbook[%d]=%d != ntt[%d]=%d", i, cs[i], i, cn[i])
					}
				}
			}

			// Public dispatcher
			cd, err := Mul(a, b)
			if err != nil {
				t.Fatalf("Mul: %v", err)
			}
			checkKAT(t, "Mul", cd, tc.sum, tc.first, tc.last)
		})
	}
}

func checkKAT(t *testing.T, label string, c []uint64, wantSum, wantFirst, wantLast uint64) {
	t.Helper()
	var sum uint64
	for _, v := range c {
		sum = (sum + v) % Q
		if v >= Q {
			t.Fatalf("%s: out-of-range value %d (Q=%d)", label, v, Q)
		}
	}
	if sum != wantSum {
		t.Fatalf("%s: sum got %d want %d", label, sum, wantSum)
	}
	if c[0] != wantFirst {
		t.Fatalf("%s: first got %d want %d", label, c[0], wantFirst)
	}
	if c[len(c)-1] != wantLast {
		t.Fatalf("%s: last got %d want %d", label, c[len(c)-1], wantLast)
	}
}

// TestNegacyclicHandwritten exercises three small explicit cases so the
// negacyclic wrap is on record: c = a*b mod (X^n + 1).
func TestNegacyclicHandwritten(t *testing.T) {
	// (1 + 2X + 3X^2 + 4X^3) * (5 + 6X + 7X^2 + 8X^3) mod (X^4+1)
	// = 5 + 16X + 34X^2 + 60X^3 + 61X^4 + 52X^5 + 32X^6
	//   wrap: subtract 61, 52, 32 from coeffs 0,1,2
	// = (5-61) + (16-52)X + (34-32)X^2 + 60X^3
	// = -56 + -36X + 2X^2 + 60X^3
	// reduced mod Q: 998244297 + 998244317X + 2X^2 + 60X^3
	a := []uint64{1, 2, 3, 4}
	b := []uint64{5, 6, 7, 8}
	want := []uint64{998244297, 998244317, 2, 60}
	got, err := MulSchoolbook(a, b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("schoolbook coef[%d] got %d want %d", i, got[i], want[i])
		}
	}
	got2, err := MulNTT(a, b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got2[i] != want[i] {
			t.Errorf("ntt coef[%d] got %d want %d", i, got2[i], want[i])
		}
	}

	// (X) * (1 + X + X^2 + X^3) mod (X^4+1)
	// = X + X^2 + X^3 + X^4 -> -1 + X + X^2 + X^3 = (Q-1) + X + X^2 + X^3
	got, err = MulSchoolbook([]uint64{0, 1, 0, 0}, []uint64{1, 1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	want = []uint64{Q - 1, 1, 1, 1}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("X*Sigma coef[%d] got %d want %d", i, got[i], want[i])
		}
	}

	// 1 * 1 = 1
	got, err = MulSchoolbook([]uint64{1, 0, 0, 0}, []uint64{1, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	want = []uint64{1, 0, 0, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("1*1 coef[%d] got %d want %d", i, got[i], want[i])
		}
	}
}

// TestNTTRoundtrip checks that NTTForward composed with NTTInverse is identity.
func TestNTTRoundtrip(t *testing.T) {
	for logN := 1; logN <= 10; logN++ {
		n := 1 << logN
		a := lcg(uint64(logN)*0x1234567, n)
		original := make([]uint64, n)
		copy(original, a)
		if err := NTTForward(a); err != nil {
			t.Fatal(err)
		}
		if err := NTTInverse(a); err != nil {
			t.Fatal(err)
		}
		for i := range a {
			if a[i] != original[i] {
				t.Fatalf("logN=%d roundtrip differs at %d: got %d want %d", logN, i, a[i], original[i])
			}
		}
	}
}

// TestPrimitiveRootProperties asserts the published constants are correct.
func TestPrimitiveRootProperties(t *testing.T) {
	// (Q-1) must be divisible by 2^MaxLogN
	if (Q-1)%(1<<MaxLogN) != 0 {
		t.Fatalf("Q-1=%d is not divisible by 2^%d", Q-1, MaxLogN)
	}
	// PrimitiveRoot^(2^MaxLogN) == 1
	if v := powMod(PrimitiveRoot, 1<<MaxLogN); v != 1 {
		t.Fatalf("PrimitiveRoot^(2^%d) = %d, want 1", MaxLogN, v)
	}
	// PrimitiveRoot^(2^(MaxLogN-1)) != 1
	if v := powMod(PrimitiveRoot, 1<<(MaxLogN-1)); v == 1 {
		t.Fatalf("PrimitiveRoot is not primitive: ^(2^%d) = 1", MaxLogN-1)
	}
}
