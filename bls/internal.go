// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"github.com/cloudflare/circl/ecc/bls12381"
)

// internalPublicKey wraps a G1 point for public keys
type internalPublicKey struct {
	point bls12381.G1
}

// internalSignature wraps a G2 point for signatures
type internalSignature struct {
	point bls12381.G2
}

// publicKeyFromG1 creates a PublicKey from a G1 point
func publicKeyFromG1(g1 *bls12381.G1) *internalPublicKey {
	return &internalPublicKey{point: *g1}
}

// signatureFromG2 creates a Signature from a G2 point
func signatureFromG2(g2 *bls12381.G2) *internalSignature {
	return &internalSignature{point: *g2}
}

// aggregateG1Points aggregates multiple G1 points (public keys)
func aggregateG1Points(points []*bls12381.G1) (*bls12381.G1, error) {
	if len(points) == 0 {
		return nil, ErrNoPublicKeys
	}

	// Start with the first point
	result := new(bls12381.G1)
	*result = *points[0]

	// Add the rest of the points
	for i := 1; i < len(points); i++ {
		result.Add(result, points[i])
	}

	return result, nil
}

// aggregateG2Points aggregates multiple G2 points (signatures)
func aggregateG2Points(points []*bls12381.G2) (*bls12381.G2, error) {
	if len(points) == 0 {
		return nil, ErrNoSignatures
	}

	// Start with the first point
	result := new(bls12381.G2)
	*result = *points[0]

	// Add the rest of the points
	for i := 1; i < len(points); i++ {
		result.Add(result, points[i])
	}

	return result, nil
}

// bytesToG1 deserializes bytes into a G1 point
func bytesToG1(data []byte) (*bls12381.G1, error) {
	g1 := new(bls12381.G1)
	if err := g1.SetBytes(data); err != nil {
		return nil, err
	}
	return g1, nil
}

// bytesToG2 deserializes bytes into a G2 point
func bytesToG2(data []byte) (*bls12381.G2, error) {
	g2 := new(bls12381.G2)
	if err := g2.SetBytes(data); err != nil {
		return nil, err
	}
	return g2, nil
}
