// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// gpu_nocgo.go — pure-Go CPU public surface for HQC's hot GF(2)^N
// operations. Activates when CGO is disabled (no PQClean / accel
// linkage).
//
// This is NOT a stub. The heavy lifting (bit-sliced Karatsuba
// multiplication, reduction mod X^N - 1, constant-time base_mul) lives
// in gpu_polymul_purego.go, which is tag-neutral so the SAME pure-Go
// implementation also backs the cgo build's fallback (see gpu_cgo.go).
// This file only exposes the public !cgo entry points:
//
//	GF2Polymul(mode, c, a, b)   c(x) = a(x) * b(x) mod (X^n - 1)
//	GF2Add(c, a, b)             c[i] = a[i] ^ b[i]      (constant time)
//
// Determinism / constant-time guarantees and references are documented
// on the shared helpers in gpu_polymul_purego.go.
//
// --- Batch GPU dispatchers ------------------------------------------
//
// batchEncapsulateGPU / batchDecapsulateGPU are defined in gpu.go.
// Without cgo, accel/ops/code's stub surface returns
// code.ErrNativeHQCUnavailable, and crypto/hqc's caller falls back to
// the single-item CPU path (which itself is cgo-only and will hit
// backend_stub.go's ErrBackendNotWired unless built with
// -tags=hqc_pqclean).

package hqc

// GF2Add computes c[i] = a[i] ^ b[i] over GF(2)^N. Constant-time on
// secret inputs (no branches, no secret-indexed loads). Operates over
// whatever slice length the caller provides — typically VecNSize64.
//
// Used by HQC's encapsulation step (PKE.Encrypt: u = r1 + h*r2 + e).
func GF2Add(c, a, b []uint64) {
	gf2AddGo(c, a, b)
}

// GF2Polymul computes c(x) = a(x) * b(x) mod (X^n - 1) in GF(2)[X]
// for ONE polynomial. All three buffers must be length VecNSize64.
//
// Implementation: bit-sliced Karatsuba recursion with the mul1 base
// case, identical to PQClean's vect_mul (reference C code). See
// gpu_polymul_purego.go.
func GF2Polymul(mode Mode, c, a, b []uint64) error {
	return polymulGo(mode, c, a, b)
}
