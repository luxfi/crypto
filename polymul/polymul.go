// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package polymul

import (
	"errors"
	"math/bits"
)

var (
	ErrLengthMismatch = errors.New("polymul: a and b must have equal length")
	ErrModulusZero    = errors.New("polymul: modulus must be non-zero")
)

// MulNegacyclic multiplies two polynomials a and b in Z_q[X] / (X^N + 1).
// a, b, and the returned polynomial all have length N. q must be non-zero.
//
// Schoolbook O(N^2). For N up to 256 this is the simplest correct path.
// For production lattice work use NTT-based multiplication.
func MulNegacyclic(a, b []uint64, q uint64) ([]uint64, error) {
	n := len(a)
	if n != len(b) {
		return nil, ErrLengthMismatch
	}
	if q == 0 {
		return nil, ErrModulusZero
	}
	c := make([]uint64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			t := mulMod(a[i], b[j], q)
			k := i + j
			if k < n {
				c[k] = addMod(c[k], t, q)
			} else {
				c[k-n] = subMod(c[k-n], t, q)
			}
		}
	}
	return c, nil
}

func addMod(a, b, q uint64) uint64 {
	s := a + b
	if s >= q {
		s -= q
	}
	return s
}

func subMod(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return q - (b - a)
}

func mulMod(a, b, q uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, q)
	return rem
}
