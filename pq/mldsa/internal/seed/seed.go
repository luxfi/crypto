// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package seed implements the shared FIPS 204 §5.1 ξ derivation rule used
// by every mldsaXX.NewKeyFromSeed entry point.
//
// FIPS 204 §5.1 KeyGen consumes a 32-byte seed ξ. Our deterministic-keygen
// callers (HD wallets, validator provisioners, DKG round seeds) frequently
// hand us seeds wider than 32 bytes — BIP-32 child seeds, HKDF outputs,
// SHAKE-derived chain segments. Rather than push that branch into every
// call site, we standardise the contract here:
//
//   - len(seed) <  SeedSize  → reject (FIPS 204 minimum violated)
//   - len(seed) == SeedSize  → use the seed as ξ verbatim
//   - len(seed) >  SeedSize  → ξ = cSHAKE-256(seed, N="", S=customization)
//
// The customization string S is per parameter set (e.g. "LUX/FIPS204/MLDSA65/seed")
// so a single oversized parent seed cannot collide across mldsa44/65/87 — and
// equally cannot collide with any other primitive that uses cSHAKE-256 with
// a different S.
//
// NIST SP 800-185 §3.3 defines cSHAKE: when N is empty and S is non-empty,
// the function is cSHAKE_256(X, L, N="", S) and is distinct from raw
// SHAKE-256 on the same input — exactly the domain separation we want.
package seed

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// SeedSize is the FIPS 204 §5.1 KeyGen ξ length in bytes.
// All three parameter sets (mldsa44, mldsa65, mldsa87) use the same ξ size.
const SeedSize = 32

// ErrSeedTooShort is returned when the caller-supplied seed has fewer than
// SeedSize bytes. FIPS 204 §5.1 mandates a 32-byte ξ; rejecting short
// inputs prevents accidentally seeding KeyGen with low-entropy material.
var ErrSeedTooShort = errors.New("mldsa: seed must be at least 32 bytes (FIPS 204 §5.1)")

// Expand reduces seed to the 32-byte ξ that FIPS 204 §5.1 KeyGen consumes.
//
// customization is the cSHAKE-256 S parameter (NIST SP 800-185 §3.3) used
// for parameter-set domain separation. Pass the per-parameter-set label
// ("LUX/FIPS204/MLDSA44/seed", etc.) so an oversized parent seed cannot
// produce colliding ξ across security levels.
//
// out is written in place so the caller controls the lifetime of the
// expanded ξ (allowing callers to wipe it after KeyGen returns).
func Expand(seed []byte, customization []byte, out *[SeedSize]byte) error {
	if len(seed) < SeedSize {
		return fmt.Errorf("%w: got %d bytes", ErrSeedTooShort, len(seed))
	}
	if len(seed) == SeedSize {
		copy(out[:], seed)
		return nil
	}

	// len(seed) > SeedSize: cSHAKE-256 with the per-parameter-set
	// customization string. Empty N matches SP 800-185 §3.3's "plain"
	// cSHAKE — the customization S alone provides domain separation.
	h := sha3.NewCShake256(nil, customization)
	if _, err := h.Write(seed); err != nil {
		return fmt.Errorf("mldsa seed expand: cshake write: %w", err)
	}
	if _, err := h.Read(out[:]); err != nil {
		return fmt.Errorf("mldsa seed expand: cshake read: %w", err)
	}
	return nil
}
