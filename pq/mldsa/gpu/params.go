// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU/CPU-accelerated FIPS 204 (ML-DSA) primitives.
//
// All three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) share the
// same polynomial ring R_q = Z_q[X]/(X^N+1) with
//
//	N = 256
//	Q = 8380417 = 2^23 - 2^13 + 1
//
// Only the matrix dimensions (k, ℓ), secret-key width η, challenge weight
// τ, signature norms (β, γ_1, γ_2), and hint bound ω vary between modes.
// One NTT kernel and one parameter table therefore serve all three
// security levels — exactly the FIPS 204 §4 design.
//
// The package exposes:
//
//   - A pure-Go CPU implementation of the negacyclic NTT and INTT over
//     R_q, with constant-time arithmetic on the verify side.
//   - A CGO-backed dispatch to github.com/luxfi/accel which uses the
//     Metal / CUDA / WebGPU backends from luxfi/accel for batched NTT
//     and batched ML-DSA sign/verify across modes {2, 3, 5}.
//
// The CPU and GPU paths produce byte-identical output (verify is
// deterministic per FIPS 204 §5.3; sign is deterministic in non-hedged
// mode). KAT-level equivalence is asserted in the test suite.
package gpu

// FIPS 204 ring constants. These are fixed across all three parameter
// sets and are the only inputs to the NTT kernel.
const (
	// N is the polynomial degree (FIPS 204 §2.3).
	N = 256

	// Q is the prime modulus 2^23 - 2^13 + 1 = 8380417 (FIPS 204 §2.3).
	//
	// Q is a 23-bit NTT-friendly prime: Q ≡ 1 (mod 2N), so a primitive
	// 2N-th root of unity exists in Z_Q. The chosen root is ζ = 1753
	// (FIPS 204 Appendix B).
	Q uint32 = 8380417

	// Zeta is the primitive 512-th root of unity used by the FIPS 204
	// NTT (FIPS 204 Appendix B). ζ^N = -1 mod Q, ζ^(2N) = 1 mod Q.
	Zeta uint32 = 1753

	// QInv is -Q^{-1} mod 2^32, used by Montgomery reduction
	// (FIPS 204 Appendix B). QInv * Q ≡ -1 (mod 2^32).
	QInv uint32 = 58728449

	// MontR is 2^32 mod Q. Used as the constant "1" in Montgomery
	// representation.
	MontR uint32 = 4193792
)

// Mode identifies a FIPS 204 parameter set by its NIST security level.
// The integer encoding matches the standard's "mode" naming (2 = Level 2,
// 3 = Level 3, 5 = Level 5) so callers can pass it directly to the
// accel.LatticeOps.MLDSASignBatch / MLDSAVerifyBatch API.
type Mode uint8

const (
	// ModeMLDSA44 is FIPS 204 ML-DSA-44 (NIST Level 2).
	ModeMLDSA44 Mode = 2
	// ModeMLDSA65 is FIPS 204 ML-DSA-65 (NIST Level 3, canonical Lux PQ).
	ModeMLDSA65 Mode = 3
	// ModeMLDSA87 is FIPS 204 ML-DSA-87 (NIST Level 5, high-value tier).
	ModeMLDSA87 Mode = 5
)

// String returns the canonical FIPS 204 name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeMLDSA44:
		return "ML-DSA-44"
	case ModeMLDSA65:
		return "ML-DSA-65"
	case ModeMLDSA87:
		return "ML-DSA-87"
	default:
		return "ML-DSA-invalid"
	}
}

// Params holds the FIPS 204 parameter set for one security level.
// Per FIPS 204 §4, only the matrix shape (K × L), secret-key width Eta,
// challenge weight Tau, signature norms Gamma1Bits / Gamma2 / Beta, and
// hint bound Omega vary between modes. All schemes share the same ring
// (N=256, Q=8380417), so a single NTT kernel serves all three.
type Params struct {
	// Mode is the NIST level identifier (2, 3, or 5).
	Mode Mode

	// Name is the canonical FIPS 204 algorithm name.
	Name string

	// K is the number of rows in matrix A and length of vectors t, w, r
	// (FIPS 204 §4 Table 1).
	K int

	// L is the number of columns in matrix A and length of vectors s, y, z
	// (FIPS 204 §4 Table 1).
	L int

	// Eta is the bound on secret-key coefficients (s ∈ S_η^ℓ × S_η^k).
	Eta int

	// Tau is the Hamming weight of the challenge polynomial c.
	Tau int

	// Beta is the bound on |c·s|: Beta = Tau * Eta.
	Beta int

	// Gamma1Bits is log_2(γ_1) — controls the y-coefficient sampling range
	// (FIPS 204 §4 Table 1).
	Gamma1Bits int

	// Gamma1 is the bound on coefficients of y (FIPS 204 §4).
	// Gamma1 = 2^Gamma1Bits.
	Gamma1 int

	// Gamma2 is the low-order rounding threshold (FIPS 204 §4 Table 1).
	Gamma2 int

	// Omega is the maximum number of 1's in the hint h
	// (FIPS 204 §4 Table 1).
	Omega int

	// PublicKeySize is the encoded public-key length in bytes.
	PublicKeySize int

	// PrivateKeySize is the encoded private-key length in bytes.
	PrivateKeySize int

	// SignatureSize is the encoded signature length in bytes.
	SignatureSize int

	// CTildeSize is the length of the commitment hash c~ in bytes
	// (FIPS 204 §4 Table 1).
	CTildeSize int
}

// allParams holds the canonical FIPS 204 parameter sets, indexed by mode.
// Values match FIPS 204 §4 Table 1 (NIST FIPS 204 2024-08-13).
//
//nolint:gochecknoglobals // FIPS 204 standard constants
var allParams = map[Mode]Params{
	ModeMLDSA44: {
		Mode:           ModeMLDSA44,
		Name:           "ML-DSA-44",
		K:              4,
		L:              4,
		Eta:            2,
		Tau:            39,
		Beta:           39 * 2, // tau * eta
		Gamma1Bits:     17,
		Gamma1:         1 << 17, // 131072
		Gamma2:         95232,   // (Q-1)/88
		Omega:          80,
		PublicKeySize:  1312,
		PrivateKeySize: 2560,
		SignatureSize:  2420,
		CTildeSize:     32,
	},
	ModeMLDSA65: {
		Mode:           ModeMLDSA65,
		Name:           "ML-DSA-65",
		K:              6,
		L:              5,
		Eta:            4,
		Tau:            49,
		Beta:           49 * 4,
		Gamma1Bits:     19,
		Gamma1:         1 << 19, // 524288
		Gamma2:         261888,  // (Q-1)/32
		Omega:          55,
		PublicKeySize:  1952,
		PrivateKeySize: 4032,
		SignatureSize:  3309,
		CTildeSize:     48,
	},
	ModeMLDSA87: {
		Mode:           ModeMLDSA87,
		Name:           "ML-DSA-87",
		K:              8,
		L:              7,
		Eta:            2,
		Tau:            60,
		Beta:           60 * 2,
		Gamma1Bits:     19,
		Gamma1:         1 << 19,
		Gamma2:         261888,
		Omega:          75,
		PublicKeySize:  2592,
		PrivateKeySize: 4896,
		SignatureSize:  4627,
		CTildeSize:     64,
	},
}

// ParamsFor returns the FIPS 204 parameter set for the given mode.
// Returns the zero Params and false for an unknown mode; callers
// MUST check the boolean before consuming the value.
func ParamsFor(m Mode) (Params, bool) {
	p, ok := allParams[m]
	return p, ok
}

// MustParamsFor returns the FIPS 204 parameter set for the given mode
// and panics on an unknown mode. Use in test code or static call sites
// where the mode is a compile-time constant.
func MustParamsFor(m Mode) Params {
	p, ok := allParams[m]
	if !ok {
		panic("mldsa/gpu: unknown ML-DSA mode " + m.String())
	}
	return p
}

// AllModes returns the canonical FIPS 204 modes in ascending NIST-level
// order: {ML-DSA-44, ML-DSA-65, ML-DSA-87}. Useful for iterating cross-
// mode test vectors.
func AllModes() []Mode {
	return []Mode{ModeMLDSA44, ModeMLDSA65, ModeMLDSA87}
}
