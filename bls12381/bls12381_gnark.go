// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || no_blst
// +build !cgo no_blst

// Package bls12381 provides BLS12-381 elliptic curve operations using gnark-crypto.
// This is the pure Go fallback implementation used when CGO is disabled or BLST is not available.
package bls12381

import (
	"crypto/rand"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PublicKey represents a BLS public key (G1 point) for gnark backend
type PublicKey struct {
	point *bls12381.G1Affine
}

// Signature represents a BLS signature (G2 point) for gnark backend
type Signature struct {
	point *bls12381.G2Affine
}

// SecretKey represents a BLS secret key for gnark backend
type SecretKey struct {
	scalar *big.Int
}

// AggregatePublicKey represents an aggregated public key for gnark backend
type AggregatePublicKey struct {
	point *bls12381.G1Affine
}

// AggregateSignature represents an aggregated signature for gnark backend
type AggregateSignature struct {
	point *bls12381.G2Affine
}

// GenerateKey generates a new random secret key
func GenerateKey() (*SecretKey, error) {
	scalar, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return &SecretKey{scalar: scalar}, nil
}

// GenerateKeyFromSeed generates a secret key from a seed
func GenerateKeyFromSeed(seed []byte) (*SecretKey, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed must be at least 32 bytes")
	}
	scalar := new(big.Int).SetBytes(seed[:32])
	scalar.Mod(scalar, fr.Modulus())
	return &SecretKey{scalar: scalar}, nil
}

// GetPublicKey derives the public key from a secret key
func (sk *SecretKey) GetPublicKey() *PublicKey {
	if sk == nil || sk.scalar == nil {
		return nil
	}
	
	_, _, g1Gen, _ := bls12381.Generators()
	
	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1Gen, sk.scalar)
	
	return &PublicKey{point: &pk}
}

// Sign signs a message with the secret key
func (sk *SecretKey) Sign(message []byte, dst []byte) (*Signature, error) {
	if sk == nil || sk.scalar == nil {
		return nil, fmt.Errorf("invalid secret key")
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}
	
	// Hash message to G2
	msgPoint, err := bls12381.HashToG2(message, dst)
	if err != nil {
		return nil, err
	}
	
	// Multiply by secret key
	var sig bls12381.G2Affine
	sig.ScalarMultiplication(&msgPoint, sk.scalar)
	
	return &Signature{point: &sig}, nil
}

// Verify verifies a signature against a public key and message
func (pk *PublicKey) Verify(message []byte, signature *Signature, dst []byte) bool {
	if pk == nil || pk.point == nil || signature == nil || signature.point == nil {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}
	
	// Hash message to G2
	msgPoint, err := bls12381.HashToG2(message, dst)
	if err != nil {
		return false
	}
	
	// Get generators
	_, _, g1Gen, _ := bls12381.Generators()
	
	// Prepare pairing check: e(pk, msgPoint) == e(g1, sig)
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)
	
	// Check e(pk, msgPoint) * e(-g1, sig) == 1
	result, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{*pk.point, negG1},
		[]bls12381.G2Affine{msgPoint, *signature.point},
	)
	
	return err == nil && result
}

// FastAggregateVerify verifies an aggregated signature for the same message
func FastAggregateVerify(pubkeys []*PublicKey, message []byte, signature *Signature, dst []byte) bool {
	if len(pubkeys) == 0 || signature == nil || signature.point == nil {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}
	
	// Aggregate public keys
	aggPk, err := AggregatePubKeys(pubkeys)
	if err != nil {
		return false
	}
	
	// Verify aggregated signature
	pk := &PublicKey{point: aggPk.point}
	return pk.Verify(message, signature, dst)
}

// AggregateVerify verifies an aggregated signature for different messages
func AggregateVerify(pubkeys []*PublicKey, messages [][]byte, signature *Signature, dst []byte) bool {
	if len(pubkeys) == 0 || len(pubkeys) != len(messages) || signature == nil {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}
	
	// For different messages, we need to verify each pairing
	// This is a simplified implementation
	for i := range pubkeys {
		if pubkeys[i] == nil || pubkeys[i].point == nil {
			return false
		}
	}
	
	// TODO: Implement proper aggregate verification for different messages
	return false
}

// AggregatePubKeys aggregates multiple public keys
func AggregatePubKeys(pubkeys []*PublicKey) (*AggregatePublicKey, error) {
	if len(pubkeys) == 0 {
		return nil, ErrEmptyInput
	}
	
	// Start with identity
	var result bls12381.G1Jac
	result.FromAffine(pubkeys[0].point)
	
	// Add remaining keys
	for i := 1; i < len(pubkeys); i++ {
		if pubkeys[i] == nil || pubkeys[i].point == nil {
			return nil, ErrInvalidPublicKey
		}
		var pk bls12381.G1Jac
		pk.FromAffine(pubkeys[i].point)
		result.AddAssign(&pk)
	}
	
	var resultAffine bls12381.G1Affine
	resultAffine.FromJacobian(&result)
	return &AggregatePublicKey{point: &resultAffine}, nil
}

// AggregateSignatures aggregates multiple signatures
func AggregateSignatures(signatures []*Signature) (*AggregateSignature, error) {
	if len(signatures) == 0 {
		return nil, ErrEmptyInput
	}
	
	// Start with identity
	var result bls12381.G2Jac
	result.FromAffine(signatures[0].point)
	
	// Add remaining signatures
	for i := 1; i < len(signatures); i++ {
		if signatures[i] == nil || signatures[i].point == nil {
			return nil, ErrInvalidSignature
		}
		var sig bls12381.G2Jac
		sig.FromAffine(signatures[i].point)
		result.AddAssign(&sig)
	}
	
	var resultAffine bls12381.G2Affine
	resultAffine.FromJacobian(&result)
	return &AggregateSignature{point: &resultAffine}, nil
}

// BatchVerify verifies multiple signatures in a batch
func BatchVerify(pubkeys []*PublicKey, messages [][]byte, signatures []*Signature, dst []byte) bool {
	if len(pubkeys) != len(messages) || len(pubkeys) != len(signatures) {
		return false
	}
	if len(pubkeys) == 0 {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}
	
	// Simple implementation: verify each individually
	for i := range pubkeys {
		if !pubkeys[i].Verify(messages[i], signatures[i], dst) {
			return false
		}
	}
	
	return true
}

// Serialize methods

// Serialize serializes a public key to compressed format
func (pk *PublicKey) Serialize() []byte {
	if pk == nil || pk.point == nil {
		return nil
	}
	return pk.point.Marshal()
}

// Deserialize deserializes a public key from compressed format
func (pk *PublicKey) Deserialize(data []byte) error {
	point := new(bls12381.G1Affine)
	if err := point.Unmarshal(data); err != nil {
		return err
	}
	pk.point = point
	return nil
}

// Serialize serializes a signature to compressed format
func (sig *Signature) Serialize() []byte {
	if sig == nil || sig.point == nil {
		return nil
	}
	return sig.point.Marshal()
}

// Deserialize deserializes a signature from compressed format
func (sig *Signature) Deserialize(data []byte) error {
	point := new(bls12381.G2Affine)
	if err := point.Unmarshal(data); err != nil {
		return err
	}
	sig.point = point
	return nil
}

// Serialize serializes a secret key
func (sk *SecretKey) Serialize() []byte {
	if sk == nil || sk.scalar == nil {
		return nil
	}
	bytes := sk.scalar.Bytes()
	// Pad to 32 bytes
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		return padded
	}
	return bytes[:32]
}

// Deserialize deserializes a secret key
func (sk *SecretKey) Deserialize(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid secret key length: expected 32, got %d", len(data))
	}
	scalar := new(big.Int).SetBytes(data)
	scalar.Mod(scalar, fr.Modulus())
	sk.scalar = scalar
	return nil
}

// Helper functions

// NewPublicKey creates a new public key from bytes
func NewPublicKey(data []byte) (*PublicKey, error) {
	pk := &PublicKey{}
	if err := pk.Deserialize(data); err != nil {
		return nil, err
	}
	return pk, nil
}

// NewSignature creates a new signature from bytes
func NewSignature(data []byte) (*Signature, error) {
	sig := &Signature{}
	if err := sig.Deserialize(data); err != nil {
		return nil, err
	}
	return sig, nil
}

// NewSecretKey creates a new secret key from bytes
func NewSecretKey(data []byte) (*SecretKey, error) {
	sk := &SecretKey{}
	if err := sk.Deserialize(data); err != nil {
		return nil, err
	}
	return sk, nil
}

// Equal checks if two public keys are equal
func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	if pk.point == nil || other.point == nil {
		return pk.point == other.point
	}
	return pk.point.Equal(other.point)
}

// Equal checks if two signatures are equal
func (sig *Signature) Equal(other *Signature) bool {
	if sig == nil || other == nil {
		return sig == other
	}
	if sig.point == nil || other.point == nil {
		return sig.point == other.point
	}
	return sig.point.Equal(other.point)
}

// Fp is a field element in Fp
type Fp = fp.Element

// Fr is a field element in Fr  
type Fr = fr.Element

// G1Affine re-exports for compatibility
type G1Affine = bls12381.G1Affine

// G2Affine re-exports for compatibility
type G2Affine = bls12381.G2Affine

// GT re-exports for compatibility
type GT = bls12381.GT

// E12 re-exports for compatibility
type E12 = bls12381.E12