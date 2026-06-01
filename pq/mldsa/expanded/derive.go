// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package expanded

import (
	"golang.org/x/crypto/sha3"
)

// FIPS 204 polynomial constants for every ML-DSA parameter set.
const (
	// polyN is the degree-bound N of every ML-DSA polynomial.
	polyN = 256

	// polyQ is the prime modulus q = 2²³ − 2¹³ + 1 = 8 380 417.
	polyQ uint32 = 8380417

	// polyCoeffMask masks the 23-bit coefficient sample drawn from
	// the SHAKE-128 squeeze; samples ≥ polyQ are rejected (FIPS 204
	// §3.6.3 RejNTTPoly).
	polyCoeffMask uint32 = 0x7fffff

	// polyPackedSize is the byte length of a single 23-bit-packed
	// polynomial: ⌈N · 23 / 8⌉ = 736 bytes (exact, no padding).
	polyPackedSize = (polyN * 23) / 8

	// shake128Rate is the SHAKE-128 output rate in bytes.
	shake128Rate = 168
)

// deriveExpandedA fills dst with the byte-packed FIPS 204 §3.6.3
// matrix A derived from rho for a K×L parameter set.
//
// The on-wire layout is row-major:
//
//	A[0,0] || A[0,1] || ... || A[0,L-1]
//	A[1,0] || ...
//	...
//	A[K-1,0] || ... || A[K-1,L-1]
//
// where each A[i,j] is one polynomial of N=256 23-bit-packed
// coefficients (polyPackedSize = 736 bytes). Total length is
// K * L * polyPackedSize and must equal len(dst).
//
// The polynomial at (i,j) is sampled from SHAKE-128 keyed by
// (rho ‖ nonce_le16) where nonce = (i<<8) | j — matching the FIPS 204
// ExpandA construction and the encoding used by CIRCL's internal
// verifier so the two derivations produce identical coefficients.
//
// Coefficients are stored as little-endian uint32 < polyQ, packed at
// 23 bits each (so 8 coefficients fit in 23 bytes — see packCoeffs).
func deriveExpandedA(dst []byte, rho *[32]byte, k, l int) {
	var poly [polyN]uint32
	off := 0
	for i := 0; i < k; i++ {
		for j := 0; j < l; j++ {
			nonce := uint16(i<<8) | uint16(j)
			rejSampleNTTPoly(&poly, rho, nonce)
			packCoeffs(dst[off:off+polyPackedSize], &poly)
			off += polyPackedSize
		}
	}
}

// rejSampleNTTPoly implements FIPS 204 Algorithm 32 RejNTTPoly: it
// draws SHAKE-128 output keyed by (rho ‖ nonce_le16) and accepts
// each 23-bit group < q as one polynomial coefficient, rejecting
// otherwise, until N coefficients are accepted.
//
// The construction is equivalent to CIRCL's PolyDeriveUniform with
// the SHAKE-128 rate of 168 bytes; we re-derive coefficients here
// independently of CIRCL's internal API.
func rejSampleNTTPoly(p *[polyN]uint32, rho *[32]byte, nonce uint16) {
	var iv [34]byte
	copy(iv[:32], rho[:])
	iv[32] = byte(nonce)
	iv[33] = byte(nonce >> 8)

	h := sha3.NewShake128()
	_, _ = h.Write(iv[:])

	var buf [shake128Rate]byte
	idx := 0
	for idx < polyN {
		_, _ = h.Read(buf[:])
		// Three squeezed bytes -> one 24-bit little-endian word ->
		// mask to 23 bits -> accept iff < q. 168 / 3 = 56 trials per
		// squeezed block; the rate is divisible by 3 so we never
		// straddle a refill boundary.
		for off := 0; off+3 <= shake128Rate && idx < polyN; off += 3 {
			t := uint32(buf[off]) |
				(uint32(buf[off+1]) << 8) |
				(uint32(buf[off+2]) << 16)
			t &= polyCoeffMask
			if t < polyQ {
				p[idx] = t
				idx++
			}
		}
	}
}

// packCoeffs serializes 256 23-bit coefficients into 736 bytes,
// little-endian, bit-packed contiguously (no padding between
// coefficients). It is the inverse of unpackCoeffs (used by tests).
//
// The encoding is canonical: identical inputs always produce
// identical outputs, byte-for-byte, on every platform. This is what
// makes the expanded form usable as a fingerprintable cache.
func packCoeffs(dst []byte, p *[polyN]uint32) {
	// Group of 8 coefficients = 8 × 23 = 184 bits = 23 bytes.
	// 256 / 8 = 32 groups, 32 × 23 = 736 bytes.
	for g := 0; g < polyN/8; g++ {
		c := p[g*8 : g*8+8]
		out := dst[g*23 : g*23+23]
		// Pack c[0..7] into a 64-bit + 64-bit + 64-bit accumulator
		// pair, then peel off bytes. We use straightforward shifts
		// rather than a clever 184-bit big-integer multiply.
		var acc [3]uint64
		acc[0] = uint64(c[0]) |
			(uint64(c[1]) << 23) |
			(uint64(c[2]) << 46)
		// c[2] occupies bits 46..68; high 5 bits spill into acc[1].
		acc[1] = uint64(c[2])>>(64-46) |
			(uint64(c[3]) << (69 - 64)) |
			(uint64(c[4]) << (92 - 64)) |
			(uint64(c[5]) << (115 - 64))
		// c[5] occupies bits 115..137; high 13 bits spill into acc[2].
		acc[2] = uint64(c[5])>>(128-115) |
			(uint64(c[6]) << (138 - 128)) |
			(uint64(c[7]) << (161 - 128))

		// Emit 23 bytes little-endian, drawn from the three 64-bit
		// limbs. Bytes 0..7 from acc[0], 8..15 from acc[1], 16..22
		// from acc[2] (only 7 bytes — bit 184 is exactly past the
		// end of c[7], so byte 22 contains the top 8 bits of c[7]).
		for b := 0; b < 8; b++ {
			out[b] = byte(acc[0] >> (8 * b))
		}
		for b := 0; b < 8; b++ {
			out[8+b] = byte(acc[1] >> (8 * b))
		}
		for b := 0; b < 7; b++ {
			out[16+b] = byte(acc[2] >> (8 * b))
		}
	}
}

// unpackCoeffs inverts packCoeffs. It is used in tests to confirm
// the pack is lossless and to compare two derivations coefficient-
// by-coefficient.
func unpackCoeffs(p *[polyN]uint32, src []byte) {
	for g := 0; g < polyN/8; g++ {
		in := src[g*23 : g*23+23]
		out := p[g*8 : g*8+8]

		var acc [3]uint64
		for b := 0; b < 8; b++ {
			acc[0] |= uint64(in[b]) << (8 * b)
		}
		for b := 0; b < 8; b++ {
			acc[1] |= uint64(in[8+b]) << (8 * b)
		}
		for b := 0; b < 7; b++ {
			acc[2] |= uint64(in[16+b]) << (8 * b)
		}

		out[0] = uint32(acc[0]) & polyCoeffMask
		out[1] = uint32(acc[0]>>23) & polyCoeffMask
		out[2] = uint32((acc[0]>>46)|(acc[1]<<18)) & polyCoeffMask
		out[3] = uint32(acc[1]>>(69-64)) & polyCoeffMask
		out[4] = uint32(acc[1]>>(92-64)) & polyCoeffMask
		out[5] = uint32((acc[1]>>(115-64))|(acc[2]<<(128-115))) & polyCoeffMask
		out[6] = uint32(acc[2]>>(138-128)) & polyCoeffMask
		out[7] = uint32(acc[2]>>(161-128)) & polyCoeffMask
	}
}
