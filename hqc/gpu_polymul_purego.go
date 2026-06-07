// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// gpu_polymul_purego.go — pure-Go GF(2)^N polynomial arithmetic shared
// by BOTH the cgo and non-cgo builds.
//
// These are the canonical pure-Go inner-loop primitives for HQC's hot
// path (bit-sliced Karatsuba multiplication + reduction mod X^N - 1).
// They have no cgo dependency, so they compile under every build tag
// and serve as the always-available fallback:
//
//   - In the !cgo build they are the only implementation (wrapped by the
//     public GF2Polymul / GF2Add in gpu_nocgo.go).
//   - In the cgo build they back the fallback in gpu_cgo.go's GF2Polymul
//     whenever the accel native HQC library is not linked (accel returns
//     code.ErrNativeHQCUnavailable in that case — see gpu_cgo.go).
//
// Determinism contract: byte-for-byte equal to PQClean's
// PQCLEAN_HQC{128,192,256}_CLEAN_vect_mul for the same inputs. The
// crypto/hqc/gpu_polymul_test.go suite cross-checks this.
//
// Constant-time guarantee: all secret-dependent operations use XOR and
// shifts only; the base_mul routine uses a constant-time masked table
// lookup. The Karatsuba recursion's structure depends ONLY on the
// per-mode constant `size` (277/561/901 for HQC-128/192/256). See the
// extended discussion in gpu_nocgo.go.
//
// Source: Brent, Gaudry, Thomé, Zimmermann, "Faster Multiplication in
// GF(2)[x]", ANTS-VIII 2008 (https://hal.inria.fr/inria-00188261v4).

package hqc

import "errors"

// ErrHQCInvalidMode is returned when a pure-Go GF(2)^N entrypoint
// receives an unknown Mode. The cgo native path mirrors this with the
// C error code.
var ErrHQCInvalidMode = errors.New("hqc: invalid mode")

// vecNSize64 returns the per-mode uint64 vector length for GF(2)^N
// polynomials. Matches PQClean's VEC_N_SIZE_64.
func vecNSize64(mode Mode) (int, error) {
	switch mode {
	case HQC128:
		return (17669 + 63) / 64, nil // 277
	case HQC192:
		return (35851 + 63) / 64, nil // 561
	case HQC256:
		return (57637 + 63) / 64, nil // 901
	default:
		return 0, ErrHQCInvalidMode
	}
}

// redMaskForMode returns the high-word mask used to clear the top
// PARAM_N-aligned bits after reduction mod (X^N - 1). Matches RED_MASK
// in PQClean's parameters.h.
func redMaskForMode(mode Mode) (uint64, int, error) {
	switch mode {
	case HQC128:
		// PARAM_N = 17669, n%64 = 5, mask = (1<<5)-1 = 0x1f
		return 0x1f, 17669, nil
	case HQC192:
		// PARAM_N = 35851, n%64 = 11, mask = (1<<11)-1 = 0x7ff
		return 0x7ff, 35851, nil
	case HQC256:
		// PARAM_N = 57637, n%64 = 37, mask = (1<<37)-1 = 0x1fffffffff
		return 0x1fffffffff, 57637, nil
	default:
		return 0, 0, ErrHQCInvalidMode
	}
}

// polymulModGo computes c(x) = a(x) * b(x) mod (X^paramN - 1) in
// GF(2)[X] for one polynomial via unsplit Karatsuba then reduction.
// Internal helper shared by the single-shot GF2Polymul wrappers in
// both builds.
func polymulModGo(c, a, b []uint64, n, paramN int, redMask uint64) error {
	// Karatsuba output: 2n words.
	oKarat := make([]uint64, 2*n)
	stack := make([]uint64, n*8)
	karatsuba(oKarat, a, b, n, stack)
	reduce(c, oKarat, n, paramN, redMask)
	return nil
}

// polymulGo is the mode-aware single-polynomial entry point: it
// validates buffer lengths and runs polymulModGo. Both build variants'
// public GF2Polymul reduce to this for the pure-Go path.
func polymulGo(mode Mode, c, a, b []uint64) error {
	n, err := vecNSize64(mode)
	if err != nil {
		return err
	}
	if len(a) != n || len(b) != n || len(c) != n {
		return errors.New("hqc: GF2Polymul buffer length mismatch")
	}
	mask, paramN, _ := redMaskForMode(mode)
	return polymulModGo(c, a, b, n, paramN, mask)
}

// gf2AddGo computes c[i] = a[i] ^ b[i] over GF(2)^N. Constant-time on
// secret inputs (no branches, no secret-indexed loads).
func gf2AddGo(c, a, b []uint64) {
	n := min3(len(a), len(b), len(c))
	// Unrolled XOR loop — the Go compiler emits SIMD-aligned XORs on
	// amd64/arm64 for this pattern. No secret-dependent branches.
	for i := 0; i < n; i++ {
		c[i] = a[i] ^ b[i]
	}
}

// karatsuba runs the recursive multiplication. Result is 2*size words.
// stack must have at least 8*size words pre-allocated.
//
// Identical structure to PQClean's gf2x.c karatsuba function — matches
// every level of recursion byte-for-byte.
func karatsuba(o, a, b []uint64, size int, stack []uint64) {
	if size == 1 {
		baseMul(o, a[0], b[0])
		return
	}
	sizeH := size / 2
	sizeL := (size + 1) / 2

	// Layout the working buffers inside `stack`:
	alh := stack[0:sizeL]
	blh := stack[sizeL : 2*sizeL]
	tmp1 := stack[2*sizeL : 4*sizeL]
	tmp2 := o[2*sizeL:]
	rest := stack[4*sizeL:]

	ah := a[sizeL:]
	bh := b[sizeL:]

	karatsuba(o, a, b, sizeL, rest)      // o[0:2*sizeL] = a_L * b_L
	karatsuba(tmp2, ah, bh, sizeH, rest) // tmp2 = a_H * b_H
	karatsubaAdd1(alh, blh, a, b, sizeL, sizeH)
	karatsuba(tmp1, alh, blh, sizeL, rest) // tmp1 = (a_L+a_H)*(b_L+b_H)
	karatsubaAdd2(o, tmp1, tmp2, sizeL, sizeH)
}

func karatsubaAdd1(alh, blh, a, b []uint64, sizeL, sizeH int) {
	for i := 0; i < sizeH; i++ {
		alh[i] = a[i] ^ a[i+sizeL]
		blh[i] = b[i] ^ b[i+sizeL]
	}
	if sizeH < sizeL {
		alh[sizeH] = a[sizeH]
		blh[sizeH] = b[sizeH]
	}
}

func karatsubaAdd2(o, tmp1, tmp2 []uint64, sizeL, sizeH int) {
	for i := 0; i < 2*sizeL; i++ {
		tmp1[i] ^= o[i]
	}
	for i := 0; i < 2*sizeH; i++ {
		tmp1[i] ^= tmp2[i]
	}
	for i := 0; i < 2*sizeL; i++ {
		o[i+sizeL] ^= tmp1[i]
	}
}

// baseMul is the constant-time 64x64-bit carryless multiplication.
// Output is 2 words (c[0] = low, c[1] = high).
//
// Direct port of PQClean's base_mul (algorithm mul1 with w=64, s=4).
// All operations on `a` and `b` are pure arithmetic on the uint64
// values — no branches, no table lookups indexed by secret bits.
func baseMul(c []uint64, a, b uint64) {
	var h, l, g uint64
	var u [16]uint64
	var maskTab [4]uint64

	// Step 1: precompute partial products u[i] = i * b (low 60 bits).
	u[0] = 0
	u[1] = b & ((uint64(1) << (64 - 4)) - 1)
	u[2] = u[1] << 1
	u[3] = u[2] ^ u[1]
	u[4] = u[2] << 1
	u[5] = u[4] ^ u[1]
	u[6] = u[3] << 1
	u[7] = u[6] ^ u[1]
	u[8] = u[4] << 1
	u[9] = u[8] ^ u[1]
	u[10] = u[5] << 1
	u[11] = u[10] ^ u[1]
	u[12] = u[6] << 1
	u[13] = u[12] ^ u[1]
	u[14] = u[7] << 1
	u[15] = u[14] ^ u[1]

	// Step 1: handle nibble 0 of a.
	g = 0
	tmp1 := a & 0x0f
	for i := uint64(0); i < 16; i++ {
		tmp2 := tmp1 - i
		// Constant-time "equal" check: mask is all-1 if tmp2 == 0.
		eqMask := uint64(0) - (1 - ((tmp2 | (0 - tmp2)) >> 63))
		g ^= u[i] & eqMask
	}
	l = g
	h = 0

	// Step 2: nibbles 1..15 of a (i = 4..60 in steps of 4).
	for i := uint64(4); i < 64; i += 4 {
		g = 0
		tmp1 = (a >> i) & 0x0f
		for j := uint64(0); j < 16; j++ {
			tmp2 := tmp1 - j
			eqMask := uint64(0) - (1 - ((tmp2 | (0 - tmp2)) >> 63))
			g ^= u[j] & eqMask
		}
		l ^= g << i
		h ^= g >> (64 - i)
	}

	// Step 3: account for the top 4 bits of b that step 1 masked off.
	maskTab[0] = 0 - ((b >> 60) & 1)
	maskTab[1] = 0 - ((b >> 61) & 1)
	maskTab[2] = 0 - ((b >> 62) & 1)
	maskTab[3] = 0 - ((b >> 63) & 1)

	l ^= (a << 60) & maskTab[0]
	h ^= (a >> 4) & maskTab[0]
	l ^= (a << 61) & maskTab[1]
	h ^= (a >> 3) & maskTab[1]
	l ^= (a << 62) & maskTab[2]
	h ^= (a >> 2) & maskTab[2]
	l ^= (a << 63) & maskTab[3]
	h ^= (a >> 1) & maskTab[3]

	c[0] = l
	c[1] = h
}

// reduce computes o(x) = a(x) mod (X^paramN - 1).
//
// Bit-shift fold: the top half of a (words [vecN .. 2*vecN - 1]) gets
// shifted down by paramN bits and XOR'd into the low half. Then the top
// word is masked to keep only the bits below paramN.
func reduce(o, a []uint64, vecN, paramN int, redMask uint64) {
	shift := uint(paramN & 0x3f)
	invShift := uint(64) - shift
	for i := 0; i < vecN; i++ {
		// PQClean dual-stream reduce: r = a[i + vecN - 1] >> shift
		//                              carry = a[i + vecN] << invShift
		// fold both into o[i]
		r := a[i+vecN-1] >> shift
		carry := a[i+vecN] << invShift
		o[i] = a[i] ^ r ^ carry
	}
	o[vecN-1] &= redMask
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
