// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hqc wraps the NIST PQC4-round selected backup KEM HQC
// (Hamming Quasi-Cyclic) — code-based, family-disjoint from Module-LWE
// ML-KEM. HQC's hardness assumption is the Syndrome Decoding Problem
// (SDP) on random linear codes, an NP-hard problem with no known
// classical or quantum polynomial-time attack. Family-disjoint from
// ML-KEM means that a structural break against MLWE (the basis of
// ML-KEM-768) does NOT compromise HQC, and vice-versa.
//
// Wired to fill the family-disjoint gap on the KEM side, parallel to
// the Pulsar / Corona / Magnetar trio on the signature side:
//
//	Signature stack:    Pulsar (MLWE)   Corona (MLWE)   Magnetar (hash)
//	KEM stack:          ML-KEM (MLWE)   —               HQC (code)
//
// Spec: NIST IR 8528 "Status Report on the Fourth Round of the NIST
// Post-Quantum Cryptography Standardization Process" (March 2025).
// Reference: https://pqc-hqc.org/.
//
// Backends:
//
//  1. PQClean cgo (default for non-stub builds). Build with
//     `-tags=hqc_pqclean`. Wires the vendored PQClean HQC reference
//     implementation under crypto/hqc/pqclean/ (public domain). NIST
//     KAT vectors verify byte-for-byte — see
//     crypto/hqc/backend_pqclean_test.go's TestKAT_HQC{128,192,256}.
//  2. Cloudflare CIRCL Go (placeholder; build tag `hqc_circl`).
//     Activates once CIRCL ships HQC support.
//  3. Stub (default). When no backend tag is set, every operation
//     returns ErrBackendNotWired so the package still compiles on
//     hosts without cgo. The wire format and parameter constants are
//     fixed by NIST IR 8528 §4.1 and remain stable across backends.
package hqc

import (
	"errors"
	"io"
)

// Mode selects the HQC parameter set. Sizes are NIST-fixed.
type Mode int

const (
	// HQC128 — NIST PQ Security Category 1 (≈ AES-128).
	// Public key: 2,249 B, ciphertext: 4,433 B, shared secret: 64 B.
	HQC128 Mode = iota

	// HQC192 — NIST PQ Security Category 3 (≈ AES-192).
	// Public key: 4,522 B, ciphertext: 8,978 B, shared secret: 64 B.
	HQC192

	// HQC256 — NIST PQ Security Category 5 (≈ AES-256).
	// Public key: 7,245 B, ciphertext: 14,421 B, shared secret: 64 B.
	HQC256
)

// Params returns the fixed sizes for the parameter set.
type Params struct {
	Mode              Mode
	PublicKeySize     int
	PrivateKeySize    int
	CiphertextSize    int
	SharedSecretSize  int
	SecurityLevelBits int // NIST PQ category mapped to ≈ AES key bits
}

// MustParamsFor returns the canonical Params for `mode` or panics on
// an unrecognised Mode. The values are byte-for-byte the PQClean
// HQC reference (https://github.com/PQClean/PQClean,
// hqc-submission_2023-04-30): see crypto/hqc/pqclean/hqc-N/clean/api.h.
//
// The ciphertext is structured as `u || v || salt` where `u` and `v`
// are the IND-CPA ciphertext halves and `salt` is a 16-byte value
// absorbed into the FO-transform hash. NIST IR 8528 §4.1 references
// this exact wire format.
func MustParamsFor(mode Mode) *Params {
	switch mode {
	case HQC128:
		return &Params{
			Mode:              HQC128,
			PublicKeySize:     2249,
			PrivateKeySize:    2305,
			CiphertextSize:    4433,
			SharedSecretSize:  64,
			SecurityLevelBits: 128,
		}
	case HQC192:
		return &Params{
			Mode:              HQC192,
			PublicKeySize:     4522,
			PrivateKeySize:    4586,
			CiphertextSize:    8978,
			SharedSecretSize:  64,
			SecurityLevelBits: 192,
		}
	case HQC256:
		return &Params{
			Mode:              HQC256,
			PublicKeySize:     7245,
			PrivateKeySize:    7317,
			CiphertextSize:    14421,
			SharedSecretSize:  64,
			SecurityLevelBits: 256,
		}
	default:
		panic("hqc: unknown mode")
	}
}

// PublicKey is an HQC encapsulation public key.
type PublicKey struct {
	Mode  Mode
	Bytes []byte
}

// PrivateKey is an HQC decapsulation private key.
type PrivateKey struct {
	Mode  Mode
	Bytes []byte
	Pub   *PublicKey
}

// Ciphertext is an HQC KEM ciphertext (encapsulation output).
type Ciphertext struct {
	Mode  Mode
	Bytes []byte
}

// Backend-wiring errors.
var (
	// ErrBackendNotWired is returned by every HQC operation until a
	// concrete backend (CIRCL HQC or PQClean cgo) is plugged in via
	// the `hqc_circl` or `hqc_pqclean` build tag.
	ErrBackendNotWired = errors.New("hqc: backend not wired — build with -tags=hqc_pqclean (cgo PQClean) or -tags=hqc_circl (once Cloudflare CIRCL ships HQC)")

	// ErrModeMismatch is returned when a public key, private key, or
	// ciphertext was generated for a different parameter set than
	// the caller is asking for.
	ErrModeMismatch = errors.New("hqc: mode mismatch between key material and requested operation")

	// ErrInvalidPublicKey, ErrInvalidPrivateKey, ErrInvalidCiphertext
	// are typed structural errors returned by the backend.
	ErrInvalidPublicKey  = errors.New("hqc: invalid public key bytes")
	ErrInvalidPrivateKey = errors.New("hqc: invalid private key bytes")
	ErrInvalidCiphertext = errors.New("hqc: invalid ciphertext bytes")
)

// KeyGen generates a fresh HQC keypair using `rng` as the entropy
// source. The public key is `params.PublicKeySize` bytes; the private
// key carries enough state to decapsulate.
//
// Class-N1-style claim (analogous to Pulsar's FIPS 204 byte equality):
// HQC.KeyGen output is bit-identical to NIST IR 8528 §4.1 reference
// keygen on the same `rng` byte stream. Backend MUST not introduce
// implementation-specific encoding differences.
func KeyGen(mode Mode, rng io.Reader) (*PrivateKey, error) {
	return backendKeyGen(mode, rng)
}

// Encapsulate runs HQC encapsulation against `pk`. Returns the
// ciphertext bytes for transmission and the derived shared secret
// (64 bytes — HQC fixes shared-secret size across all parameter sets).
//
// `rng` is consumed deterministically; replaying the same `(pk, rng)`
// produces the same `(ct, ss)` (FIPS-style determinism property).
func Encapsulate(pk *PublicKey, rng io.Reader) (ct *Ciphertext, sharedSecret []byte, err error) {
	if pk == nil {
		return nil, nil, ErrInvalidPublicKey
	}
	return backendEncapsulate(pk, rng)
}

// Decapsulate runs HQC decapsulation. Returns the 64-byte shared
// secret OR an implicit-rejection sentinel (HQC uses Hofheinz-Hövelmanns-
// Kiltz implicit rejection — never returns a hard error on a tampered
// ciphertext; instead derives a pseudorandom 64-byte string from the
// secret key + ciphertext, which an honest counterparty would not
// match).
func Decapsulate(sk *PrivateKey, ct *Ciphertext) (sharedSecret []byte, err error) {
	if sk == nil {
		return nil, ErrInvalidPrivateKey
	}
	if ct == nil {
		return nil, ErrInvalidCiphertext
	}
	if sk.Mode != ct.Mode {
		return nil, ErrModeMismatch
	}
	return backendDecapsulate(sk, ct)
}

// Public returns the companion public key.
func (sk *PrivateKey) Public() *PublicKey {
	if sk == nil {
		return nil
	}
	return sk.Pub
}
