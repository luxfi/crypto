// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mldsa44 implements the ML-DSA-44 (NIST Level 2) parameter set
// of FIPS 204 with both random and deterministic keygen.
//
// See github.com/luxfi/crypto/pq/mldsa for the parameter-set overview;
// this file is the Level 2 counterpart of mldsa65 and mldsa87. The API
// surface is identical across parameter sets, so callers can switch
// security levels by changing one import line.
package mldsa44

import (
	"errors"
	"fmt"
	"io"

	circl "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/internal/seed"
)

// Size constants. The ξ length is fixed at 32 bytes for every FIPS 204
// parameter set; the public / private / signature sizes are NIST Level 2.
const (
	// SeedSize is the FIPS 204 §5.1 ξ length in bytes.
	SeedSize = seed.SeedSize

	// PublicKeySize is the encoded ML-DSA-44 public key length.
	PublicKeySize = circl.PublicKeySize

	// PrivateKeySize is the encoded ML-DSA-44 private key length.
	PrivateKeySize = circl.PrivateKeySize

	// SignatureSize is the encoded ML-DSA-44 signature length.
	SignatureSize = circl.SignatureSize
)

// PublicKey is the ML-DSA-44 public key. Aliased to the upstream type so
// callers can interoperate with code that consumes either path.
type PublicKey = circl.PublicKey

// PrivateKey is the ML-DSA-44 private key. Aliased to the upstream type.
type PrivateKey = circl.PrivateKey

// seedCustomization is the cSHAKE-256 S parameter (NIST SP 800-185 §3.3)
// used by NewKeyFromSeed when expanding an oversized parent seed down to
// the 32-byte ξ FIPS 204 §5.1 consumes. The label binds the resulting ξ
// to ML-DSA-44 so the same parent seed cannot collide with mldsa65 or
// mldsa87.
var seedCustomization = []byte("LUX/FIPS204/MLDSA44/seed")

// GenerateKey draws a uniformly random keypair using entropy from rand.
// If rand is nil, crypto/rand.Reader is used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := circl.GenerateKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa44 generate: %w", err)
	}
	return pk, sk, nil
}

// NewKeyFromSeed deterministically derives an ML-DSA-44 keypair from the
// supplied seed (FIPS 204 §5.1 KeyGen from ξ).
//
// The seed contract follows the Lux pq/mldsa convention:
//
//   - len(seed) <  SeedSize (32) → returns ErrSeedTooShort.
//   - len(seed) == SeedSize       → used verbatim as ξ.
//   - len(seed) >  SeedSize       → reduced to ξ via
//     cSHAKE-256(seed, N="", S="LUX/FIPS204/MLDSA44/seed").
//
// The cSHAKE customization string provides per-parameter-set domain
// separation: the same parent seed handed to mldsa44.NewKeyFromSeed and
// mldsa65.NewKeyFromSeed yields independent keypairs.
func NewKeyFromSeed(s []byte) (*PublicKey, *PrivateKey, error) {
	var xi [SeedSize]byte
	if err := seed.Expand(s, seedCustomization, &xi); err != nil {
		return nil, nil, err
	}
	pk, sk := circl.NewKeyFromSeed(&xi)
	// Wipe the local ξ buffer; the seed material now lives inside sk.
	for i := range xi {
		xi[i] = 0
	}
	return pk, sk, nil
}

// Sign signs msg with sk and domain-separating context ctx. Per FIPS 204
// §5.2, ctx is bound into the signature; callers SHOULD pass a non-empty,
// protocol-specific ctx to prevent cross-protocol signature replay.
// ctx may be at most 255 bytes.
func Sign(sk *PrivateKey, msg, ctx []byte, randomized bool) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("mldsa44 sign: private key is nil")
	}
	sig := make([]byte, SignatureSize)
	if err := circl.SignTo(sk, msg, ctx, randomized, sig); err != nil {
		return nil, fmt.Errorf("mldsa44 sign: %w", err)
	}
	return sig, nil
}

// Verify reports whether sig is a valid ML-DSA-44 signature on msg under
// pk with domain-separating context ctx (FIPS 204 §5.3). ctx must match
// the value passed to Sign; ctx may be at most 255 bytes.
func Verify(pk *PublicKey, msg, ctx, sig []byte) bool {
	if pk == nil {
		return false
	}
	return circl.Verify(pk, msg, ctx, sig)
}
