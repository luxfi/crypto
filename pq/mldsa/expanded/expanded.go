// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package expanded

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// ParamSet identifies the FIPS 204 parameter set the expanded key is bound to.
// The wire byte layouts are not interchangeable across sets; ParamSet is
// stored in PublicKey so a misrouted Verify call fails closed.
type ParamSet uint8

const (
	// MLDSA44 is the NIST Level 2 parameter set (K=4, L=4).
	MLDSA44 ParamSet = 44
	// MLDSA65 is the NIST Level 3 parameter set (K=6, L=5).
	MLDSA65 ParamSet = 65
	// MLDSA87 is the NIST Level 5 parameter set (K=8, L=7).
	MLDSA87 ParamSet = 87
)

// String returns the canonical parameter-set label.
func (p ParamSet) String() string {
	switch p {
	case MLDSA44:
		return "ML-DSA-44"
	case MLDSA65:
		return "ML-DSA-65"
	case MLDSA87:
		return "ML-DSA-87"
	default:
		return fmt.Sprintf("ML-DSA-?(%d)", p)
	}
}

// params returns the (K, L, compactSize, expandedASize) tuple for a set.
func (p ParamSet) params() (k, l, compactSize, expandedASize int, ok bool) {
	switch p {
	case MLDSA44:
		return 4, 4, mldsa44.PublicKeySize, 4 * 4 * polyPackedSize, true
	case MLDSA65:
		return 6, 5, mldsa65.PublicKeySize, 6 * 5 * polyPackedSize, true
	case MLDSA87:
		return 8, 7, mldsa87.PublicKeySize, 8 * 7 * polyPackedSize, true
	default:
		return 0, 0, 0, 0, false
	}
}

// Size constants. ExpandedASize<param> reports the number of bytes
// occupied by the precomputed matrix A for the named parameter set
// using the 23-bit packed encoding documented in doc.go.
const (
	ExpandedASize44 = 4 * 4 * polyPackedSize //  11,776 bytes
	ExpandedASize65 = 6 * 5 * polyPackedSize //  22,080 bytes
	ExpandedASize87 = 8 * 7 * polyPackedSize //  41,216 bytes
)

// PublicKey is an EIP-8051-style expanded ML-DSA public key.
//
// Compact holds the FIPS 204 §6.4 encoding (ρ ‖ t1) verbatim — i.e.,
// the exact bytes a canonical mldsaXX.PublicKey serializes to. The
// 32-byte ρ prefix is also the seed that determines ExpandedA.
//
// ExpandedA holds the K×L polynomials of the matrix A in NTT-domain,
// 23-bit packed (matching the coefficient bound q − 1 < 2²³). It is
// fully recomputable from Compact[:32] (ρ); the field exists so that
// throughput-sensitive verifiers can amortize the SHAKE-128 expansion
// over many signatures. A nil/short ExpandedA is treated as "no
// cache present" and Expand() recomputes it.
type PublicKey struct {
	Set       ParamSet
	Compact   []byte
	ExpandedA []byte
}

// Common errors. They are returned, never panicked, even on
// malformed inputs — Verify is a boundary function.
var (
	// ErrUnknownParamSet is returned when Set is not 44/65/87.
	ErrUnknownParamSet = errors.New("mldsa expanded: unknown parameter set")
	// ErrCompactSize is returned when Compact has the wrong length for Set.
	ErrCompactSize = errors.New("mldsa expanded: compact key size mismatch")
	// ErrExpandedASize is returned when ExpandedA has the wrong length for Set.
	ErrExpandedASize = errors.New("mldsa expanded: expanded-A size mismatch")
	// ErrExpandedAMismatch is returned by Verify when the carried
	// ExpandedA does not match the deterministic re-expansion of ρ.
	// A caller seeing this error is holding a corrupted or
	// tampered cache.
	ErrExpandedAMismatch = errors.New("mldsa expanded: ExpandedA does not match ρ")
)

// Expand returns the expanded form of an ML-DSA-XX compact public key.
// The parameter set is inferred from len(compact).
//
// The returned PublicKey owns a freshly-allocated ExpandedA derived
// from compact[:32] (ρ). The Compact field is a copy of the input.
func Expand(compact []byte) (*PublicKey, error) {
	set, err := paramSetFromCompactSize(len(compact))
	if err != nil {
		return nil, err
	}
	return ExpandSet(set, compact)
}

// ExpandSet is the explicit-parameter-set form of Expand. It returns
// ErrCompactSize if len(compact) does not match Set.
func ExpandSet(set ParamSet, compact []byte) (*PublicKey, error) {
	k, l, compactSize, expandedSize, ok := set.params()
	if !ok {
		return nil, ErrUnknownParamSet
	}
	if len(compact) != compactSize {
		return nil, fmt.Errorf("%w: %s want %d, got %d",
			ErrCompactSize, set, compactSize, len(compact))
	}

	pk := &PublicKey{
		Set:       set,
		Compact:   append([]byte(nil), compact...),
		ExpandedA: make([]byte, expandedSize),
	}
	var rho [32]byte
	copy(rho[:], compact[:32])
	deriveExpandedA(pk.ExpandedA, &rho, k, l)
	return pk, nil
}

// Compact returns the canonical FIPS 204 §6.4 encoding of pk (ρ ‖ t1).
// The returned slice is a copy; callers may mutate it without
// affecting pk. The ExpandedA cache is intentionally dropped — round-
// tripping through Compact() and Expand() is the documented way to
// shed a precomputed matrix from a serialized form.
func Compact(pk *PublicKey) []byte {
	if pk == nil {
		return nil
	}
	return append([]byte(nil), pk.Compact...)
}

// Verify reports whether sig is a valid ML-DSA signature on (msg, ctx)
// under pk. It enforces three invariants in order:
//
//  1. pk.Set is one of MLDSA44/65/87.
//  2. len(pk.Compact) matches the wire size for pk.Set.
//  3. pk.ExpandedA, if present, matches a fresh re-expansion of ρ;
//     a mismatch returns false (a tampered cache cannot bias verify).
//
// Once the cache check passes, Verify delegates to the canonical
// FIPS 204 verifier in crypto/pq/mldsa/mldsaXX. The cache is the
// optimization; the FIPS-204 path is the authority.
func Verify(pk *PublicKey, msg, ctx, sig []byte) bool {
	if pk == nil {
		return false
	}
	k, l, compactSize, expandedSize, ok := pk.Set.params()
	if !ok {
		return false
	}
	if len(pk.Compact) != compactSize {
		return false
	}
	if pk.ExpandedA != nil {
		if len(pk.ExpandedA) != expandedSize {
			return false
		}
		var rho [32]byte
		copy(rho[:], pk.Compact[:32])
		fresh := make([]byte, expandedSize)
		deriveExpandedA(fresh, &rho, k, l)
		if !bytesEqual(fresh, pk.ExpandedA) {
			return false
		}
	}
	return verifyCompact(pk.Set, pk.Compact, msg, ctx, sig)
}

// verifyCompact wraps the per-parameter-set canonical verifier so
// Verify can dispatch on Set without importing the typed key in this
// file's API surface.
func verifyCompact(set ParamSet, compact, msg, ctx, sig []byte) bool {
	switch set {
	case MLDSA44:
		var raw [mldsa44.PublicKeySize]byte
		copy(raw[:], compact)
		var pk mldsa44.PublicKey
		pk.Unpack(&raw)
		return mldsa44.Verify(&pk, msg, ctx, sig)
	case MLDSA65:
		var raw [mldsa65.PublicKeySize]byte
		copy(raw[:], compact)
		var pk mldsa65.PublicKey
		pk.Unpack(&raw)
		return mldsa65.Verify(&pk, msg, ctx, sig)
	case MLDSA87:
		var raw [mldsa87.PublicKeySize]byte
		copy(raw[:], compact)
		var pk mldsa87.PublicKey
		pk.Unpack(&raw)
		return mldsa87.Verify(&pk, msg, ctx, sig)
	default:
		return false
	}
}

// paramSetFromCompactSize maps a compact-key length to its parameter
// set. The three FIPS 204 sizes are distinct, so the mapping is
// unambiguous.
func paramSetFromCompactSize(n int) (ParamSet, error) {
	switch n {
	case mldsa44.PublicKeySize:
		return MLDSA44, nil
	case mldsa65.PublicKeySize:
		return MLDSA65, nil
	case mldsa87.PublicKeySize:
		return MLDSA87, nil
	default:
		return 0, fmt.Errorf("%w: unrecognized compact size %d",
			ErrCompactSize, n)
	}
}

// bytesEqual is constant-time at the byte level for our fixed-size
// cache comparison. We don't need full constant-time semantics here
// (the cache contents are public, derived from ρ which is itself
// public), but a straight bytes.Equal is fine and we avoid the
// stdlib import dependency.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
