// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU/CPU-accelerated FIPS 205 (SLH-DSA) primitives.
//
// SLH-DSA is the stateless hash-based signature standard ratified by NIST in
// August 2024 as the final form of SPHINCS+. The FIPS 205 §10 catalogue
// defines twelve parameter sets across three NIST security levels and two
// inner-hash families:
//
//	            +-------------+--------------+
//	            |  SHA2 inner |  SHAKE inner |
//	+-----------+-------------+--------------+
//	| L1 small  |  SHA2-128s  |  SHAKE-128s  |
//	| L1 fast   |  SHA2-128f  |  SHAKE-128f  |
//	| L3 small  |  SHA2-192s  |  SHAKE-192s  |
//	| L3 fast   |  SHA2-192f  |  SHAKE-192f  | <- canonical Magnetar profile
//	| L5 small  |  SHA2-256s  |  SHAKE-256s  |
//	| L5 fast   |  SHA2-256f  |  SHAKE-256f  |
//	+-----------+-------------+--------------+
//
// "fast" parameter sets keep signature size large (~35 KB at L3) for sub-
// second signing; "small" sets shrink the signature (~16 KB at L3) at the
// cost of a 50× slowdown in signing. Lux ships the 'f' variants for the
// validator quorum path (signing latency dominates wall-clock finality),
// while the 's' variants are available for archival / one-shot signing.
//
// The package exposes:
//
//   - The FIPS 205 §10 parameter table (n, h, d, h', a, k, lg_w, m, security
//     in bits, public/private key/signature byte sizes) for every set.
//   - A SignBatch dispatcher that forwards into the canonical
//     github.com/luxfi/crypto/slhdsa.SignBatch entry point. That entry
//     point implements the full GPU→goroutine-parallel→serial fallback
//     ladder so we don't duplicate the dispatch logic here.
//
// The CPU and GPU paths produce byte-identical output (FIPS 205 §10.2
// SignDeterministic has no per-call randomness — the per-sign nonce is
// derived from PRF(sk_prf, opt_rand, msg) and we set opt_rand to a fixed
// zero string per FIPS 205 deterministic mode). KAT-level equivalence is
// asserted in the test suite.
package gpu

// FIPS 205 §10 catalogue constants. Most are derived from a single n
// parameter (n = 16/24/32 for L1/L3/L5) so the table-driven dispatch in
// params.go is the canonical source.
const (
	// FORSHeightMin / FORSHeightMax bracket the FORS tree height a across
	// the FIPS 205 parameter sets. The 's' (small) variants use a=12; the
	// 'f' (fast) variants use a=6 or a=9 depending on level.
	FORSHeightMin = 6
	FORSHeightMax = 14

	// HypertreeLayersMin / HypertreeLayersMax bracket the hypertree depth d
	// across the FIPS 205 parameter sets. The 's' variants use d=7; the 'f'
	// variants use d=17 or d=22 (more layers, smaller XMSS subtrees,
	// shorter signing latency).
	HypertreeLayersMin = 7
	HypertreeLayersMax = 22

	// WOTSWBits is log2(w) where w is the Winternitz parameter. FIPS 205
	// fixes w=16 for every parameter set, so WOTSWBits = 4.
	WOTSWBits = 4
)

// Mode identifies a FIPS 205 parameter set by the (security level, hash
// family, size variant) tuple. The integer encoding matches the values
// the lux-accel C ABI consumes (see luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp).
type Mode uint8

const (
	// ModeSHA2_128s is FIPS 205 SLH-DSA-SHA2-128s (NIST L1, small).
	ModeSHA2_128s Mode = 1
	// ModeSHA2_128f is FIPS 205 SLH-DSA-SHA2-128f (NIST L1, fast).
	ModeSHA2_128f Mode = 2
	// ModeSHA2_192s is FIPS 205 SLH-DSA-SHA2-192s (NIST L3, small).
	ModeSHA2_192s Mode = 4
	// ModeSHA2_192f is FIPS 205 SLH-DSA-SHA2-192f (NIST L3, fast).
	// Canonical Magnetar / Lux recovery-path profile.
	ModeSHA2_192f Mode = 3
	// ModeSHA2_256s is FIPS 205 SLH-DSA-SHA2-256s (NIST L5, small).
	ModeSHA2_256s Mode = 6
	// ModeSHA2_256f is FIPS 205 SLH-DSA-SHA2-256f (NIST L5, fast).
	ModeSHA2_256f Mode = 5

	// ModeSHAKE_128s is FIPS 205 SLH-DSA-SHAKE-128s (NIST L1, small).
	ModeSHAKE_128s Mode = 11
	// ModeSHAKE_128f is FIPS 205 SLH-DSA-SHAKE-128f (NIST L1, fast).
	ModeSHAKE_128f Mode = 12
	// ModeSHAKE_192s is FIPS 205 SLH-DSA-SHAKE-192s (NIST L3, small).
	ModeSHAKE_192s Mode = 14
	// ModeSHAKE_192f is FIPS 205 SLH-DSA-SHAKE-192f (NIST L3, fast).
	ModeSHAKE_192f Mode = 13
	// ModeSHAKE_256s is FIPS 205 SLH-DSA-SHAKE-256s (NIST L5, small).
	ModeSHAKE_256s Mode = 16
	// ModeSHAKE_256f is FIPS 205 SLH-DSA-SHAKE-256f (NIST L5, fast).
	ModeSHAKE_256f Mode = 15
)

// String returns the canonical FIPS 205 name of the mode.
func (m Mode) String() string {
	if p, ok := allParams[m]; ok {
		return p.Name
	}
	return "SLH-DSA-invalid"
}

// IsFast reports whether the mode is one of the 'f' (fast) variants.
// Only fast variants are wired through the GPU substrate; the 's' (small)
// variants stay CPU-only since the FIPS 205 catalogue lists them as
// bandwidth-optimised, not throughput-optimised.
func (m Mode) IsFast() bool {
	if p, ok := allParams[m]; ok {
		return p.Fast
	}
	return false
}

// SecurityLevel returns the NIST security category (1, 3, or 5) for the
// mode. Returns 0 for an unknown mode.
func (m Mode) SecurityLevel() int {
	if p, ok := allParams[m]; ok {
		return p.NISTLevel
	}
	return 0
}

// Params holds the FIPS 205 parameter set for one (level, hash, variant)
// combination. Per FIPS 205 §10 the meaningful axes of variation are:
//
//   - N           : hash output width in bytes (16 / 24 / 32)
//   - H           : total tree height (= H' * D)
//   - D           : number of hypertree layers
//   - HPrime      : per-layer XMSS subtree height (H / D)
//   - A           : FORS tree height
//   - K           : number of FORS trees
//   - LgW         : log2(w), fixed at 4
//   - M           : message digest length in bytes
//
// All inner constants are derived; the byte sizes (public/private key,
// signature) follow from §10 and are pinned by the FIPS 205 KAT vectors
// already covered in github.com/luxfi/crypto/slhdsa.
type Params struct {
	// Mode is the integer mode identifier.
	Mode Mode

	// Name is the canonical FIPS 205 algorithm name
	// (e.g. "SLH-DSA-SHA2-192f").
	Name string

	// NISTLevel is 1, 3, or 5.
	NISTLevel int

	// Fast is true for the 'f' (fast) variants, false for 's' (small).
	Fast bool

	// SHAKE is true when the inner hash family is SHAKE-256; false for the
	// SHA-2 family (SHA-256 + SHA-512 for L3/L5).
	SHAKE bool

	// N is the hash output width in bytes (FIPS 205 §10 Table 2).
	N int

	// H is the total hypertree height (FIPS 205 §10 Table 2).
	// H = D * HPrime by construction.
	H int

	// D is the number of XMSS layers in the hypertree (FIPS 205 §10).
	D int

	// HPrime is the per-layer XMSS subtree height (FIPS 205 §10).
	HPrime int

	// A is the FORS tree height (FIPS 205 §10).
	A int

	// K is the number of FORS trees (FIPS 205 §10).
	K int

	// LgW is log2(w) where w is the Winternitz parameter
	// (fixed at 4 across all FIPS 205 parameter sets).
	LgW int

	// M is the message digest length in bytes used by H_msg (FIPS 205 §10).
	M int

	// PublicKeySize is the encoded public-key length in bytes (= 2*N).
	PublicKeySize int

	// PrivateKeySize is the encoded private-key length in bytes (= 4*N).
	PrivateKeySize int

	// SignatureSize is the encoded signature length in bytes (FIPS 205 §10).
	SignatureSize int

	// SecurityBits is the claimed concrete security in bits against the
	// best-known attack (FIPS 205 §10 Table 2 — collision-resistance limit
	// dominates for the SLH-DSA hash families).
	SecurityBits int
}

// allParams holds the canonical FIPS 205 parameter sets, indexed by mode.
// Values match FIPS 205 §10 Tables 2/3 (FIPS 205 final, 2024-08-13).
//
//nolint:gochecknoglobals // FIPS 205 standard constants
var allParams = map[Mode]Params{
	// --- NIST Level 1 (128-bit collision-resistance target) -----------------

	ModeSHA2_128s: {
		Mode: ModeSHA2_128s, Name: "SLH-DSA-SHA2-128s",
		NISTLevel: 1, Fast: false, SHAKE: false,
		N: 16, H: 63, D: 7, HPrime: 9, A: 12, K: 14, LgW: 4, M: 30,
		PublicKeySize: 32, PrivateKeySize: 64,
		SignatureSize: 7856, SecurityBits: 128,
	},
	ModeSHAKE_128s: {
		Mode: ModeSHAKE_128s, Name: "SLH-DSA-SHAKE-128s",
		NISTLevel: 1, Fast: false, SHAKE: true,
		N: 16, H: 63, D: 7, HPrime: 9, A: 12, K: 14, LgW: 4, M: 30,
		PublicKeySize: 32, PrivateKeySize: 64,
		SignatureSize: 7856, SecurityBits: 128,
	},
	ModeSHA2_128f: {
		Mode: ModeSHA2_128f, Name: "SLH-DSA-SHA2-128f",
		NISTLevel: 1, Fast: true, SHAKE: false,
		N: 16, H: 66, D: 22, HPrime: 3, A: 6, K: 33, LgW: 4, M: 34,
		PublicKeySize: 32, PrivateKeySize: 64,
		SignatureSize: 17088, SecurityBits: 128,
	},
	ModeSHAKE_128f: {
		Mode: ModeSHAKE_128f, Name: "SLH-DSA-SHAKE-128f",
		NISTLevel: 1, Fast: true, SHAKE: true,
		N: 16, H: 66, D: 22, HPrime: 3, A: 6, K: 33, LgW: 4, M: 34,
		PublicKeySize: 32, PrivateKeySize: 64,
		SignatureSize: 17088, SecurityBits: 128,
	},

	// --- NIST Level 3 (192-bit collision-resistance target) -----------------

	ModeSHA2_192s: {
		Mode: ModeSHA2_192s, Name: "SLH-DSA-SHA2-192s",
		NISTLevel: 3, Fast: false, SHAKE: false,
		N: 24, H: 63, D: 7, HPrime: 9, A: 14, K: 17, LgW: 4, M: 39,
		PublicKeySize: 48, PrivateKeySize: 96,
		SignatureSize: 16224, SecurityBits: 192,
	},
	ModeSHAKE_192s: {
		Mode: ModeSHAKE_192s, Name: "SLH-DSA-SHAKE-192s",
		NISTLevel: 3, Fast: false, SHAKE: true,
		N: 24, H: 63, D: 7, HPrime: 9, A: 14, K: 17, LgW: 4, M: 39,
		PublicKeySize: 48, PrivateKeySize: 96,
		SignatureSize: 16224, SecurityBits: 192,
	},
	// SHA2-192f is the canonical Magnetar / Lux recovery-path profile.
	ModeSHA2_192f: {
		Mode: ModeSHA2_192f, Name: "SLH-DSA-SHA2-192f",
		NISTLevel: 3, Fast: true, SHAKE: false,
		N: 24, H: 66, D: 22, HPrime: 3, A: 8, K: 33, LgW: 4, M: 42,
		PublicKeySize: 48, PrivateKeySize: 96,
		SignatureSize: 35664, SecurityBits: 192,
	},
	ModeSHAKE_192f: {
		Mode: ModeSHAKE_192f, Name: "SLH-DSA-SHAKE-192f",
		NISTLevel: 3, Fast: true, SHAKE: true,
		N: 24, H: 66, D: 22, HPrime: 3, A: 8, K: 33, LgW: 4, M: 42,
		PublicKeySize: 48, PrivateKeySize: 96,
		SignatureSize: 35664, SecurityBits: 192,
	},

	// --- NIST Level 5 (256-bit collision-resistance target) -----------------

	ModeSHA2_256s: {
		Mode: ModeSHA2_256s, Name: "SLH-DSA-SHA2-256s",
		NISTLevel: 5, Fast: false, SHAKE: false,
		N: 32, H: 64, D: 8, HPrime: 8, A: 14, K: 22, LgW: 4, M: 47,
		PublicKeySize: 64, PrivateKeySize: 128,
		SignatureSize: 29792, SecurityBits: 256,
	},
	ModeSHAKE_256s: {
		Mode: ModeSHAKE_256s, Name: "SLH-DSA-SHAKE-256s",
		NISTLevel: 5, Fast: false, SHAKE: true,
		N: 32, H: 64, D: 8, HPrime: 8, A: 14, K: 22, LgW: 4, M: 47,
		PublicKeySize: 64, PrivateKeySize: 128,
		SignatureSize: 29792, SecurityBits: 256,
	},
	ModeSHA2_256f: {
		Mode: ModeSHA2_256f, Name: "SLH-DSA-SHA2-256f",
		NISTLevel: 5, Fast: true, SHAKE: false,
		N: 32, H: 68, D: 17, HPrime: 4, A: 9, K: 35, LgW: 4, M: 49,
		PublicKeySize: 64, PrivateKeySize: 128,
		SignatureSize: 49856, SecurityBits: 256,
	},
	ModeSHAKE_256f: {
		Mode: ModeSHAKE_256f, Name: "SLH-DSA-SHAKE-256f",
		NISTLevel: 5, Fast: true, SHAKE: true,
		N: 32, H: 68, D: 17, HPrime: 4, A: 9, K: 35, LgW: 4, M: 49,
		PublicKeySize: 64, PrivateKeySize: 128,
		SignatureSize: 49856, SecurityBits: 256,
	},
}

// ParamsFor returns the FIPS 205 parameter set for the given mode.
// Returns the zero Params and false for an unknown mode; callers MUST
// check the boolean before consuming the value.
func ParamsFor(m Mode) (Params, bool) {
	p, ok := allParams[m]
	return p, ok
}

// MustParamsFor returns the FIPS 205 parameter set for the given mode
// and panics on an unknown mode. Use in test code or static call sites
// where the mode is a compile-time constant.
func MustParamsFor(m Mode) Params {
	p, ok := allParams[m]
	if !ok {
		panic("slhdsa/gpu: unknown SLH-DSA mode " + m.String())
	}
	return p
}

// AllModes returns the canonical FIPS 205 modes in ascending NIST-level
// order, with 's' variants first within each level. Useful for iterating
// cross-mode test vectors.
func AllModes() []Mode {
	return []Mode{
		ModeSHA2_128s, ModeSHAKE_128s, ModeSHA2_128f, ModeSHAKE_128f,
		ModeSHA2_192s, ModeSHAKE_192s, ModeSHA2_192f, ModeSHAKE_192f,
		ModeSHA2_256s, ModeSHAKE_256s, ModeSHA2_256f, ModeSHAKE_256f,
	}
}

// FastModes returns only the 'f' (fast) FIPS 205 modes — the ones eligible
// for GPU dispatch. The 's' (small) modes stay CPU-only.
func FastModes() []Mode {
	return []Mode{
		ModeSHA2_128f, ModeSHAKE_128f,
		ModeSHA2_192f, ModeSHAKE_192f,
		ModeSHA2_256f, ModeSHAKE_256f,
	}
}

// CanonicalMagnetar is the Lux recovery-path profile: SLH-DSA-SHA2-192f.
// NIST L3, deterministic, FIPS 205 §10 catalogue entry SLH-DSA-SHA2-192f.
const CanonicalMagnetar = ModeSHA2_192f
