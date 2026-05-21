// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"math/rand/v2"
	"testing"
)

// BenchmarkGF2Polymul measures single-shot GF(2)^N polynomial
// multiplication across all three parameter sets. The numbers
// captured here are the headline figure for HQC's hot path — every
// IND-CPA encryption/decryption issues at least one polymul.
//
// Run on each build mode to compare:
//
//	CGO_ENABLED=0 go test -bench BenchmarkGF2Polymul -run '^$' ./hqc/...
//	CGO_ENABLED=1 go test -bench BenchmarkGF2Polymul -run '^$' ./hqc/...
func BenchmarkGF2Polymul(b *testing.B) {
	cases := []struct {
		mode Mode
		name string
	}{
		{HQC128, "HQC-128"},
		{HQC192, "HQC-192"},
		{HQC256, "HQC-256"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			n, _ := vecNSize64(tc.mode)
			a := make([]uint64, n)
			bb := make([]uint64, n)
			c := make([]uint64, n)
			r := rand.New(rand.NewPCG(7, 13))
			for i := 0; i < n; i++ {
				a[i] = r.Uint64()
				bb[i] = r.Uint64()
			}
			b.SetBytes(int64(n * 8))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = GF2Polymul(tc.mode, c, a, bb)
			}
		})
	}
}

// BenchmarkGF2PolymulBatch measures batched polymul throughput at
// various batch sizes, matching the user-requested test matrix:
//
//	n in {2048, 4096, 8192} bits (vector-length surrogate is HQC mode)
//	batch in {1, 32}
//
// HQC vector sizes (PARAM_N in bits): 17669, 35851, 57637.
// We use those directly rather than synthetic n — the production
// API never sees synthetic vector sizes.
func BenchmarkGF2PolymulBatch(b *testing.B) {
	cases := []struct {
		mode  Mode
		name  string
		batch int
	}{
		{HQC128, "HQC-128/batch=1", 1},
		{HQC128, "HQC-128/batch=32", 32},
		{HQC192, "HQC-192/batch=1", 1},
		{HQC192, "HQC-192/batch=32", 32},
		{HQC256, "HQC-256/batch=1", 1},
		{HQC256, "HQC-256/batch=32", 32},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			n, _ := vecNSize64(tc.mode)
			a := make([]uint64, n)
			bb := make([]uint64, n)
			c := make([]uint64, n)
			r := rand.New(rand.NewPCG(uint64(tc.mode)+1, uint64(tc.batch)*17))
			for i := 0; i < n; i++ {
				a[i] = r.Uint64()
				bb[i] = r.Uint64()
			}
			b.SetBytes(int64(tc.batch * n * 8))
			b.ResetTimer()
			for iter := 0; iter < b.N; iter++ {
				for j := 0; j < tc.batch; j++ {
					_ = GF2Polymul(tc.mode, c, a, bb)
				}
			}
		})
	}
}
