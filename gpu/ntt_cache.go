// Package gpu provides GPU-accelerated cryptographic operations.
// This file implements precomputed NTT twiddle factor caching for polynomial operations.
package gpu

import (
	"sync"
)

// ML-DSA NTT parameters (FIPS 204 / Dilithium)
const (
	// MLDSA_Q is the ML-DSA prime modulus: 2^23 - 2^13 + 1 = 8380417
	MLDSA_Q int32 = 8380417

	// MLDSA_N is the ML-DSA polynomial degree
	MLDSA_N = 256

	// MLDSA_QINV is Q^(-1) mod 2^32 for Montgomery reduction
	MLDSA_QINV int32 = 58728449

	// MLDSA_MONT is 2^32 mod Q for Montgomery form
	MLDSA_MONT int32 = -4186625

	// MLDSA_ROOT is primitive 512th root of unity: 1753 (zeta in FIPS 204)
	MLDSA_ROOT int32 = 1753

	// invNTTScaleFactor is mont^2/256 = 41978 for inverse NTT scaling
	invNTTScaleFactor int32 = 41978
)

// NTTCache holds precomputed twiddle factors for NTT operations.
// Thread-safe after initialization. Immutable during use.
type NTTCache struct {
	N        int       // Polynomial degree
	Q        int32     // Prime modulus
	Zetas    [256]int32 // Forward NTT twiddle factors
}

// Global cache for ML-DSA (N=256)
var (
	mldsaCache     *NTTCache
	mldsaCacheOnce sync.Once
)

// Precomputed zetas table from ML-DSA reference (FIPS 204).
// These are powers of the primitive 512th root of unity in a specific order
// for the Cooley-Tukey NTT algorithm.
var mldsaZetas = [256]int32{
	0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
	1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
	2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
	-2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
	2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
	-3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
	-1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
	811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
	-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
	-1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
	3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
	-671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
	-3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
	-3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
	189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
	1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
	2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
	266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
	900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
	-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
	342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
	2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
	-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
	-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
	-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
	-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
	-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
	-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
	-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
	-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
	-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
	-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782,
}

// GetMLDSACache returns the precomputed NTT cache for ML-DSA (N=256, Q=8380417).
// Lazily initialized on first call. Thread-safe.
func GetMLDSACache() *NTTCache {
	mldsaCacheOnce.Do(func() {
		mldsaCache = &NTTCache{
			N:     MLDSA_N,
			Q:     MLDSA_Q,
			Zetas: mldsaZetas,
		}
	})
	return mldsaCache
}

// GetNTTCache returns a precomputed NTT cache for the given polynomial size.
// Currently only size 256 (ML-DSA) is supported.
func GetNTTCache(n int) *NTTCache {
	if n == 256 {
		return GetMLDSACache()
	}
	return nil
}

// NTT performs forward Number Theoretic Transform in-place.
// Uses Cooley-Tukey decimation-in-time algorithm.
// Output is in bit-reversed order.
// Matches FIPS 204 reference implementation exactly.
func (c *NTTCache) NTT(a []int32) {
	if len(a) != c.N {
		return
	}

	k := 0
	for length := 128; length > 0; length >>= 1 {
		for start := 0; start < c.N; start += 2 * length {
			k++
			zeta := c.Zetas[k]
			for j := start; j < start+length; j++ {
				t := montgomeryReduce(int64(zeta) * int64(a[j+length]))
				a[j+length] = a[j] - t
				a[j] = a[j] + t
			}
		}
	}
}

// InvNTT performs inverse Number Theoretic Transform in-place.
// Uses Gentleman-Sande decimation-in-frequency algorithm.
// Output is multiplied by Montgomery factor 2^32.
// Matches FIPS 204 reference implementation exactly.
func (c *NTTCache) InvNTT(a []int32) {
	if len(a) != c.N {
		return
	}

	k := 256
	for length := 1; length < c.N; length <<= 1 {
		for start := 0; start < c.N; start += 2 * length {
			k--
			zeta := -c.Zetas[k]
			for j := start; j < start+length; j++ {
				t := a[j]
				a[j] = t + a[j+length]
				a[j+length] = t - a[j+length]
				a[j+length] = montgomeryReduce(int64(zeta) * int64(a[j+length]))
			}
		}
	}

	// Scale by mont^2/256
	for j := 0; j < c.N; j++ {
		a[j] = montgomeryReduce(int64(invNTTScaleFactor) * int64(a[j]))
	}
}

// NTTBatch performs forward NTT on multiple polynomials in parallel.
func (c *NTTCache) NTTBatch(polys [][]int32) {
	var wg sync.WaitGroup
	for i := range polys {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c.NTT(polys[idx])
		}(i)
	}
	wg.Wait()
}

// InvNTTBatch performs inverse NTT on multiple polynomials in parallel.
func (c *NTTCache) InvNTTBatch(polys [][]int32) {
	var wg sync.WaitGroup
	for i := range polys {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c.InvNTT(polys[idx])
		}(i)
	}
	wg.Wait()
}

// PolyMulNTT multiplies two polynomials in NTT domain.
// Both a and b must already be in NTT form.
// Result is written to r (can be same as a or b).
func (c *NTTCache) PolyMulNTT(r, a, b []int32) {
	if len(a) != c.N || len(b) != c.N || len(r) != c.N {
		return
	}
	for i := 0; i < c.N; i++ {
		r[i] = montgomeryReduce(int64(a[i]) * int64(b[i]))
	}
}

// Reduce32 reduces coefficient to range (-Q, Q).
func Reduce32(a int32) int32 {
	t := (a + (1 << 22)) >> 23
	t = a - t*MLDSA_Q
	return t
}

// CAddQ adds Q if coefficient is negative.
func CAddQ(a int32) int32 {
	a += (a >> 31) & MLDSA_Q
	return a
}

// =============================================================================
// Montgomery Arithmetic
// =============================================================================

// montgomeryReduce computes Montgomery reduction: a * R^(-1) mod Q
// where R = 2^32. For ML-DSA Q = 8380417.
// Input: -Q*2^31 <= a < Q*2^31
// Output: -Q < result < Q
func montgomeryReduce(a int64) int32 {
	t := int32(a) * MLDSA_QINV
	return int32((a - int64(t)*int64(MLDSA_Q)) >> 32)
}

// ToMontgomery converts a to Montgomery form: a * 2^32 mod Q.
func ToMontgomery(a int32) int32 {
	return montgomeryReduce(int64(a) * int64(MLDSA_MONT) * int64(MLDSA_MONT))
}

// FromMontgomery converts from Montgomery form: a * 2^(-32) mod Q.
func FromMontgomery(a int32) int32 {
	return montgomeryReduce(int64(a))
}

// ClearNTTCaches releases all cached NTT contexts.
// Primarily for testing. New caches will be created on next access.
func ClearNTTCaches() {
	mldsaCacheOnce = sync.Once{}
	mldsaCache = nil
}
