// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package poly_mul implements polynomial multiplication over the
// canonical FFT prime Q = 998244353 = 119 * 2^23 + 1.
//
// Two paths are exposed:
//
//   - Schoolbook   O(n^2)  -- always correct, fastest below n=64
//   - NTT-based    O(n log n) for the negacyclic convolution that lattice
//                  cryptography (ML-KEM, ML-DSA, Corona) uses
//
// Q = 998244353 is the canonical FFT-friendly prime used by AtCoder, Cyclone-FFT,
// the SPOJ POLYMUL reference, and most competitive-programming NTT references.
// Its 2-adicity is 23, so the NTT supports lengths up to N = 2^23.
//
// Negacyclic convolution: c[k] = sum_{i+j=k}    a[i]*b[j]
//                              - sum_{i+j=k+n}  a[i]*b[j]
// over Z_Q[X]/(X^n + 1) with q the prime above. This is the exact shape
// used by lattice schemes; cyclic convolution is recovered by padding.
//
// All inputs/outputs are reduced mod Q. Inputs above Q are reduced on
// entry; outputs are always strictly less than Q.
package poly_mul

import (
	"errors"
	"math/bits"
)

// Q is the canonical FFT prime used here: 998244353 = 119 * 2^23 + 1.
// 2-adicity = 23 -> NTT length up to 2^23.
const Q uint64 = 998244353

// PrimitiveRoot is a 2^MaxLogN-th primitive root of unity in F_Q.
// Computed as 3^((Q-1)/2^MaxLogN) mod Q where 3 is a primitive root of F_Q.
const PrimitiveRoot uint64 = 629671588

// MaxLogN is the largest log2(n) supported by the NTT path.
// Q's 2-adicity is 23 so technically up to 23 is supported; we cap at 16
// (n=65536) which is far above ML-KEM (256), ML-DSA (256), Corona's typical
// dimensions.
const MaxLogN = 16

// ErrLength is returned when slice lengths violate the API contract.
var ErrLength = errors.New("poly_mul: invalid length")

// addMod returns (a + b) mod Q. Inputs may be in [0, Q-1].
// Since Q < 2^30, addition cannot overflow uint64.
func addMod(a, b uint64) uint64 {
	s := a + b
	if s >= Q {
		s -= Q
	}
	return s
}

// subMod returns (a - b) mod Q. Inputs may be in [0, Q-1].
func subMod(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + Q - b
}

// mulMod returns (a * b) mod Q. Q < 2^30 so a*b < 2^60 fits in uint64.
// One full-width 64-bit multiply and one division.
func mulMod(a, b uint64) uint64 {
	return (a * b) % Q
}

// powMod returns base^exp mod Q via square-and-multiply.
func powMod(base, exp uint64) uint64 {
	result := uint64(1)
	b := base % Q
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = mulMod(result, b)
		}
		b = mulMod(b, b)
		e >>= 1
	}
	return result
}

// invMod returns the modular inverse of a in F_Q via Fermat. Assumes a != 0.
func invMod(a uint64) uint64 {
	return powMod(a, Q-2)
}

// rootOfUnity returns a primitive n-th root of unity for n = 2^logN, logN in [0, MaxLogN].
func rootOfUnity(logN int) uint64 {
	if logN < 0 || logN > MaxLogN {
		panic("poly_mul: log_n out of range")
	}
	step := uint64(1) << (MaxLogN - logN)
	return powMod(PrimitiveRoot, step)
}

// bitReverseCopy permutes data in place using the bit-reversal permutation.
func bitReverseCopy(data []uint64) {
	n := len(data)
	if n <= 1 {
		return
	}
	logN := bits.TrailingZeros(uint(n))
	for i := 0; i < n; i++ {
		j := int(bits.Reverse(uint(i)) >> (bits.UintSize - logN))
		if i < j {
			data[i], data[j] = data[j], data[i]
		}
	}
}

// ntt performs an iterative Cooley-Tukey NTT in place. forward=false runs
// the inverse direction (no n^-1 scaling here -- caller multiplies).
func ntt(data []uint64, forward bool) error {
	n := len(data)
	if n == 0 || n&(n-1) != 0 || n > (1<<MaxLogN) {
		return ErrLength
	}
	logN := bits.TrailingZeros(uint(n))
	bitReverseCopy(data)
	for s := 1; s <= logN; s++ {
		m := 1 << s
		var wm uint64
		if forward {
			wm = rootOfUnity(s)
		} else {
			wm = invMod(rootOfUnity(s))
		}
		for k := 0; k < n; k += m {
			w := uint64(1)
			for j := 0; j < m/2; j++ {
				t := mulMod(w, data[k+j+m/2])
				u := data[k+j]
				data[k+j] = addMod(u, t)
				data[k+j+m/2] = subMod(u, t)
				w = mulMod(w, wm)
			}
		}
	}
	return nil
}

// NTTForward performs a forward NTT in place. data must have power-of-2
// length up to 2^MaxLogN.
func NTTForward(data []uint64) error {
	return ntt(data, true)
}

// NTTInverse performs an inverse NTT in place, including the 1/n scaling.
func NTTInverse(data []uint64) error {
	if err := ntt(data, false); err != nil {
		return err
	}
	nInv := invMod(uint64(len(data)))
	for i := range data {
		data[i] = mulMod(data[i], nInv)
	}
	return nil
}

// reduce reduces a slice element-wise mod Q (returns a fresh copy).
func reduce(a []uint64) []uint64 {
	out := make([]uint64, len(a))
	for i, v := range a {
		out[i] = v % Q
	}
	return out
}

// MulSchoolbook computes a*b in Z_Q[X]/(X^n + 1) via O(n^2) schoolbook.
// Reference path: every other path is tested against this.
func MulSchoolbook(a, b []uint64) ([]uint64, error) {
	n := len(a)
	if n == 0 || len(b) != n {
		return nil, ErrLength
	}
	ar := reduce(a)
	br := reduce(b)
	c := make([]uint64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			prod := mulMod(ar[i], br[j])
			k := i + j
			if k < n {
				c[k] = addMod(c[k], prod)
			} else {
				// Negacyclic wrap: X^n = -1
				c[k-n] = subMod(c[k-n], prod)
			}
		}
	}
	return c, nil
}

// MulNTT computes a*b in Z_Q[X]/(X^n + 1) via NTT-based negacyclic
// convolution. n must be a power of 2 in [2, 2^MaxLogN].
//
// For negacyclic convolution we need a 2n-th primitive root psi.
// Pre-multiply a[i] by psi^i and b[i] by psi^i, run length-n NTT, do
// pointwise multiply, inverse NTT, and post-multiply by psi^-i.
func MulNTT(a, b []uint64) ([]uint64, error) {
	n := len(a)
	if n == 0 || n&(n-1) != 0 || n > (1<<MaxLogN) || len(b) != n {
		return nil, ErrLength
	}
	logN := bits.TrailingZeros(uint(n))
	if logN+1 > MaxLogN {
		return nil, ErrLength
	}
	psi := rootOfUnity(logN + 1)
	psiInv := invMod(psi)

	aw := reduce(a)
	bw := reduce(b)
	psiPow := uint64(1)
	for i := 0; i < n; i++ {
		aw[i] = mulMod(aw[i], psiPow)
		bw[i] = mulMod(bw[i], psiPow)
		psiPow = mulMod(psiPow, psi)
	}

	if err := NTTForward(aw); err != nil {
		return nil, err
	}
	if err := NTTForward(bw); err != nil {
		return nil, err
	}

	c := make([]uint64, n)
	for i := 0; i < n; i++ {
		c[i] = mulMod(aw[i], bw[i])
	}

	if err := NTTInverse(c); err != nil {
		return nil, err
	}

	psiInvPow := uint64(1)
	for i := 0; i < n; i++ {
		c[i] = mulMod(c[i], psiInvPow)
		psiInvPow = mulMod(psiInvPow, psiInv)
	}

	return c, nil
}

// Mul picks the fastest correct path for the input size and returns
// a*b in Z_Q[X]/(X^n + 1). Below n=64 schoolbook wins; above, NTT.
func Mul(a, b []uint64) ([]uint64, error) {
	if len(a) == 0 || len(b) != len(a) {
		return nil, ErrLength
	}
	if len(a) < 64 || len(a)&(len(a)-1) != 0 {
		return MulSchoolbook(a, b)
	}
	return MulNTT(a, b)
}
