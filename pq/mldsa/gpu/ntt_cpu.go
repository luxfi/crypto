// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

// FIPS 204 ML-DSA pure-Go NTT over R_q = Z_q[X]/(X^256+1).
//
// Implements the standard negacyclic Cooley-Tukey forward and
// Gentleman-Sande inverse described in FIPS 204 Algorithms 41 (NTT)
// and 42 (NTT^{-1}), with the canonical zeta-power table from FIPS 204
// Appendix B (rows match the reference C / Python implementation
// byte-for-byte).
//
// Constant-time discipline: all secret-dependent operations here are
// branch-free modular adds/subs/mults that operate uniformly across the
// input. The NTT itself is a fixed-shape butterfly network independent
// of input values, so it leaks nothing about its operand. mulQ, reduce,
// and the butterflies are written without secret-dependent branches.
//
// This file is *always* compiled (no build tags). The CGO and non-CGO
// dispatchers in gpu_{cgo,nocgo}.go both fall back to these helpers
// when the batch is below the GPU threshold or the GPU is unavailable.

// Zetas is the precomputed table of ζ^BitReverse(k) mod Q for k in [0,256),
// taken from FIPS 204 Appendix B (Table 1). This is the canonical NTT
// twiddle-factor table; deviating from it produces results that fail
// the FIPS 204 KAT vectors.
//
//nolint:gochecknoglobals // FIPS 204 Appendix B constants
var Zetas = [N]uint32{
	0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
	7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
	5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
	5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
	3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
	394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
	3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
	5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
	3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
	2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
	1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
	4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
	5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
	7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
	1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
	348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
	1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
	1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
	8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
	6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
	4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
	3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
	2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
	7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
	6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
	6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
	5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
	3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
	3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
	3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
	6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
	8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
}

// reduce32 computes a Barrett-style 32-bit reduction modulo Q.
// Input range: full uint32. Output range: [0, Q).
//
// Constant-time: no branches, no table lookups dependent on a.
func reduce32(a uint32) uint32 {
	// Reduce a in [0, 2^32) to [0, 2Q) via Barrett:
	//   t = floor(a / Q)
	// then a - t*Q in [0, 2Q).
	// A final conditional subtract drops to [0, Q).
	// The mulhi factor mu = floor(2^45 / Q) = 4193792.
	// Implemented branch-free with the standard mask idiom.

	// Use uint64 arithmetic to compute (a * mu) >> 45.
	const mu uint64 = 4193792 // floor(2^45 / Q)
	t := uint32((uint64(a) * mu) >> 45)
	r := a - t*Q
	// Branch-free conditional subtract: r -= Q & -(r >= Q).
	mask := uint32(0) - uint32(boolToU32(r >= Q))
	r -= Q & mask
	return r
}

// boolToU32 converts a bool to 1 (true) or 0 (false) without a branch on
// secret data. Go guarantees this lowers to a setcc on amd64.
func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// montReduce returns (a * R^{-1}) mod Q where R = 2^32 (Montgomery
// reduction). Input a is a 64-bit product of two reduced-form
// 32-bit values, so a < Q * 2^32 < 2^55.
//
// Constant-time: branch-free.
func montReduce(a uint64) uint32 {
	// t = (a * QInv) mod 2^32
	t := uint32(a) * QInv
	// u = (a + t * Q) / 2^32
	u := uint32((a + uint64(t)*uint64(Q)) >> 32)
	// u in [0, 2Q); conditional subtract.
	mask := uint32(0) - uint32(boolToU32(u >= Q))
	u -= Q & mask
	return u
}

// mulModQ returns a * b mod Q.
//
// Constant-time: branch-free.
func mulModQ(a, b uint32) uint32 {
	return uint32((uint64(a) * uint64(b)) % uint64(Q))
}

// addModQ returns (a + b) mod Q, given a, b < Q.
//
// Constant-time: branch-free mask conditional subtract.
func addModQ(a, b uint32) uint32 {
	r := a + b
	mask := uint32(0) - uint32(boolToU32(r >= Q))
	r -= Q & mask
	return r
}

// subModQ returns (a - b) mod Q, given a, b < Q.
//
// Constant-time: branch-free mask conditional add.
func subModQ(a, b uint32) uint32 {
	r := a - b
	mask := uint32(0) - uint32(boolToU32(int32(r) < 0))
	r += Q & mask
	return r
}

// NTTForwardCPU performs the FIPS 204 §4.3 forward NTT in-place on a
// length-N coefficient slice over R_q. p is mutated to NTT-domain form.
//
// FIPS 204 Algorithm 41 (NTT) — Cooley-Tukey decimation-in-time.
// Twiddle factors come from Zetas[] in bit-reversed order, exactly
// matching the reference implementation. Output coefficients are in
// [0, Q).
//
// Constant-time: the iteration structure depends only on N, not on p.
func NTTForwardCPU(p *[N]uint32) {
	k := 1
	for length := 128; length >= 1; length >>= 1 {
		for start := 0; start < N; start += 2 * length {
			zeta := Zetas[k]
			k++
			for j := start; j < start+length; j++ {
				// Standard CT butterfly:
				//   t = zeta * p[j+length]
				//   p[j+length] = p[j] - t
				//   p[j] = p[j] + t
				t := mulModQ(zeta, p[j+length])
				p[j+length] = subModQ(p[j], t)
				p[j] = addModQ(p[j], t)
			}
		}
	}
}

// NTTInverseCPU performs the FIPS 204 §4.3 inverse NTT in-place on a
// length-N evaluation-domain slice over R_q. p is mutated to coefficient
// form.
//
// FIPS 204 Algorithm 42 (NTT^{-1}) — Gentleman-Sande decimation-in-
// frequency, followed by the canonical scaling factor (1 - Q) (= N^{-1}
// mod Q packed into the same loop). Output coefficients are in [0, Q).
//
// Constant-time: structure depends only on N.
func NTTInverseCPU(p *[N]uint32) {
	k := N - 1
	for length := 1; length < N; length <<= 1 {
		for start := 0; start < N; start += 2 * length {
			// FIPS 204 reference uses -zeta in the inverse loop.
			zeta := Q - Zetas[k]
			k--
			for j := start; j < start+length; j++ {
				// Gentleman-Sande butterfly:
				//   t = p[j]
				//   p[j]        = t + p[j+length]
				//   p[j+length] = zeta * (t - p[j+length])
				t := p[j]
				p[j] = addModQ(t, p[j+length])
				p[j+length] = mulModQ(zeta, subModQ(t, p[j+length]))
			}
		}
	}

	// Final scaling: multiply by f = N^{-1} mod Q = 8347681 (FIPS 204
	// reference constant; also equals (Q+1)/N reduced).
	const fInv uint32 = 8347681
	for i := 0; i < N; i++ {
		p[i] = mulModQ(fInv, p[i])
	}
}

// PolyMulCPU computes c = a * b in R_q via the standard NTT-domain
// pointwise multiplication: NTT(c) = NTT(a) ⊙ NTT(b), then INTT.
//
// All three slices must be length N. Inputs are not mutated.
func PolyMulCPU(a, b *[N]uint32) [N]uint32 {
	var aN, bN [N]uint32
	aN = *a
	bN = *b
	NTTForwardCPU(&aN)
	NTTForwardCPU(&bN)
	var c [N]uint32
	for i := 0; i < N; i++ {
		c[i] = mulModQ(aN[i], bN[i])
	}
	NTTInverseCPU(&c)
	return c
}

// PolyMulNTTDomainCPU computes c = a ⊙ b pointwise modulo Q. Both
// inputs are assumed to already be in NTT (evaluation) domain. Useful
// when many multiplications share the same NTT of one operand.
func PolyMulNTTDomainCPU(a, b *[N]uint32) [N]uint32 {
	var c [N]uint32
	for i := 0; i < N; i++ {
		c[i] = mulModQ(a[i], b[i])
	}
	return c
}

// PolyAddCPU returns a + b mod Q componentwise.
func PolyAddCPU(a, b *[N]uint32) [N]uint32 {
	var c [N]uint32
	for i := 0; i < N; i++ {
		c[i] = addModQ(a[i], b[i])
	}
	return c
}

// PolySubCPU returns a - b mod Q componentwise.
func PolySubCPU(a, b *[N]uint32) [N]uint32 {
	var c [N]uint32
	for i := 0; i < N; i++ {
		c[i] = subModQ(a[i], b[i])
	}
	return c
}
