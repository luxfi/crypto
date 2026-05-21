// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

// TestGF2Polymul_KAT pins the GF(2)^N polynomial multiplication
// output against fixed expected values, with the inputs generated
// deterministically from a fixed PCG seed.
//
// These vectors were captured by running this exact code with the
// cgo path enabled (which routes through libluxgpu_hqc.a, byte-equal
// to PQClean's PQCLEAN_HQC{128,192,256}_CLEAN_vect_mul). The nocgo
// pure-Go bit-sliced Karatsuba was then verified to produce
// BIT-IDENTICAL output. This is the cross-build correctness oracle:
// a regression in either path fails this test loudly.
//
// To regenerate (after a deliberate PQClean / param change):
//
//	cd ~/work/lux/crypto && CGO_ENABLED=1 go test -count=1 \
//	  -run TestGF2Polymul_KAT ./hqc/... -v
//
// Capture the printed "captured: ..." values into the table below.
//
// Verifying both build modes:
//
//	CGO_ENABLED=0 go test -count=1 -run TestGF2Polymul_KAT ./hqc/...
//	CGO_ENABLED=1 go test -count=1 -run TestGF2Polymul_KAT ./hqc/...
//
// Both must report PASS.
func TestGF2Polymul_KAT(t *testing.T) {
	cases := []struct {
		mode   Mode
		name   string
		seedA  uint64
		seedB  uint64
		first4 string // hex of c[0..3] (first 32 bytes)
	}{
		{
			mode:   HQC128,
			name:   "HQC-128",
			seedA:  0xDEADBEEFCAFEBABE,
			seedB:  0x0123456789ABCDEF,
			first4: "bc8ce7e8c6d56132c911effc03f15e0087eb1ab68e5752d8fb4c6cbf1a5673db",
		},
		{
			mode:   HQC192,
			name:   "HQC-192",
			seedA:  0xDEADBEEFCAFEBABE,
			seedB:  0x0123456789ABCDEF,
			first4: "d5c4edfec6451f84abb20366123bdd6d8560281c5d6fc7f47969c6ed7a9a55a2",
		},
		{
			mode:   HQC256,
			name:   "HQC-256",
			seedA:  0xDEADBEEFCAFEBABE,
			seedB:  0x0123456789ABCDEF,
			first4: "61fa8a58fa62b3075fe3b91f950c3c1385ac4ec1003fd212a77c9740589e7ca2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := vecNSize64(tc.mode)
			if err != nil {
				t.Fatalf("vecNSize64: %v", err)
			}
			a := make([]uint64, n)
			b := make([]uint64, n)
			c := make([]uint64, n)
			r := rand.New(rand.NewPCG(tc.seedA, tc.seedB))
			for i := 0; i < n; i++ {
				a[i] = r.Uint64()
				b[i] = r.Uint64()
			}
			if err := GF2Polymul(tc.mode, c, a, b); err != nil {
				t.Fatalf("GF2Polymul: %v", err)
			}
			got := make([]byte, 32)
			for i := 0; i < 4; i++ {
				for j := 0; j < 8; j++ {
					got[i*8+j] = byte(c[i] >> (8 * j))
				}
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tc.first4 {
				t.Fatalf("KAT mismatch for %s\n  want %s\n  got  %s\n  (regenerate with cgo path if PQClean changed)",
					tc.name, tc.first4, gotHex)
			}
		})
	}
}

// TestGF2Polymul_FixedSeedRange exercises a 100-iteration deterministic
// fuzz with fixed seeds and a byte-checksum cross-check. The seeds and
// expected checksums were captured on the cgo path; the nocgo path
// must produce identical checksums.
//
// This catches subtle bugs that the single-vector KAT might miss
// (e.g. off-by-one in the Karatsuba recursion at a specific size
// boundary). Each iteration uses a fresh PCG seed derived from `iter`.
func TestGF2Polymul_FixedSeedRange(t *testing.T) {
	cases := []struct {
		mode     Mode
		name     string
		expected string // hex of accumulated XOR-checksum of c across 100 iters
	}{
		{HQC128, "HQC-128", "a41489be492c433bb8568f1ba2c8ba9914e879c0983aee3f07a4477abc85fced"},
		{HQC192, "HQC-192", "12f23ebdead409ffe902cae9f3ee2860e0cc6aa15ff38cfd98bfc5b177eb145f"},
		{HQC256, "HQC-256", "879c4b5c6d96caf0669caf2987dbd80e49adef130ec23340080ad9a20ae985bb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, _ := vecNSize64(tc.mode)
			acc := make([]uint64, 4) // accumulate first 4 uint64s across iters
			a := make([]uint64, n)
			b := make([]uint64, n)
			c := make([]uint64, n)
			for iter := uint64(0); iter < 100; iter++ {
				r := rand.New(rand.NewPCG(iter*0x9E3779B97F4A7C15, iter*0xBF58476D1CE4E5B9+1))
				for i := 0; i < n; i++ {
					a[i] = r.Uint64()
					b[i] = r.Uint64()
				}
				if err := GF2Polymul(tc.mode, c, a, b); err != nil {
					t.Fatalf("iter=%d: %v", iter, err)
				}
				for i := 0; i < 4; i++ {
					acc[i] ^= c[i]
				}
			}
			got := make([]byte, 32)
			for i := 0; i < 4; i++ {
				for j := 0; j < 8; j++ {
					got[i*8+j] = byte(acc[i] >> (8 * j))
				}
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tc.expected {
				t.Fatalf("100-iter fuzz checksum drift for %s\n  want %s\n  got  %s",
					tc.name, tc.expected, gotHex)
			}
		})
	}
}
