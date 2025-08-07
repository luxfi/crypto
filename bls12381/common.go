// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import "errors"

// Common errors
var (
	// ErrInvalidPoint is returned when a point is invalid
	ErrInvalidPoint = errors.New("invalid point")
	// ErrInvalidScalar is returned when a scalar is invalid
	ErrInvalidScalar = errors.New("invalid scalar")
	// ErrInvalidPublicKey is returned when a public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")
	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrEmptyInput is returned when input is empty
	ErrEmptyInput = errors.New("empty input")
)

// DefaultDST is the default domain separation tag for signatures
const DefaultDST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"