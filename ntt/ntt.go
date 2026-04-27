// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ntt

import (
	"errors"
	"math/bits"
)

var (
	ErrNotPow2     = errors.New("ntt: input length must be a power of 2")
	ErrModulusZero = errors.New("ntt: modulus must be non-zero")
)

// NTT computes a forward Number-Theoretic Transform of a in-place using the
// Cooley-Tukey radix-2 algorithm modulo q. omega must be a primitive
// (len(a))-th root of unity modulo q.
//
// Pure Go reference implementation. For production lattice-crypto callers
// should use the algorithm-specific kernels in mldsa/, mlkem/, or accel
// directly; this implementation is for vector kernels and tests.
func NTT(a []uint64, omega, q uint64) error {
	n := len(a)
	if n == 0 {
		return nil
	}
	if n&(n-1) != 0 {
		return ErrNotPow2
	}
	if q == 0 {
		return ErrModulusZero
	}

	// Bit-reverse permutation.
	logN := bits.TrailingZeros(uint(n))
	for i := 0; i < n; i++ {
		j := int(bits.Reverse(uint(i)) >> (bits.UintSize - logN))
		if j > i {
			a[i], a[j] = a[j], a[i]
		}
	}

	// Iterative butterfly.
	for size := 2; size <= n; size <<= 1 {
		half := size >> 1
		// w_size = omega^(n/size) mod q
		w0 := powMod(omega, uint64(n/size), q)
		for start := 0; start < n; start += size {
			w := uint64(1)
			for k := 0; k < half; k++ {
				t := mulMod(w, a[start+k+half], q)
				u := a[start+k]
				a[start+k] = addMod(u, t, q)
				a[start+k+half] = subMod(u, t, q)
				w = mulMod(w, w0, q)
			}
		}
	}
	return nil
}

// INTT computes the inverse NTT in-place. omegaInv = omega^-1 mod q,
// nInv = n^-1 mod q.
func INTT(a []uint64, omegaInv, nInv, q uint64) error {
	if err := NTT(a, omegaInv, q); err != nil {
		return err
	}
	for i := range a {
		a[i] = mulMod(a[i], nInv, q)
	}
	return nil
}

// addMod returns (a + b) mod q.
func addMod(a, b, q uint64) uint64 {
	s := a + b
	if s >= q {
		s -= q
	}
	return s
}

// subMod returns (a - b) mod q.
func subMod(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return q - (b - a)
}

// mulMod returns (a * b) mod q using 128-bit intermediate.
func mulMod(a, b, q uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, q)
	return rem
}

// powMod returns base^exp mod q using square-and-multiply.
func powMod(base, exp, q uint64) uint64 {
	r := uint64(1)
	b := base % q
	for exp > 0 {
		if exp&1 == 1 {
			r = mulMod(r, b, q)
		}
		b = mulMod(b, b, q)
		exp >>= 1
	}
	return r
}
