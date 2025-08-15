// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && !no_blst
// +build cgo,!no_blst

// Package bls12381 provides high-performance BLS12-381 operations using BLST.
// This implementation uses the supranational/blst library for optimal performance.
package bls12381

import (
	"crypto/rand"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// PublicKey represents a BLS public key (G1 point)
type PublicKey struct {
	point *blst.P1Affine
}

// Signature represents a BLS signature (G2 point)
type Signature struct {
	point *blst.P2Affine
}

// SecretKey represents a BLS secret key
type SecretKey struct {
	scalar *blst.SecretKey
}

// AggregatePublicKey represents an aggregated public key
type AggregatePublicKey struct {
	point *blst.P1Affine
}

// AggregateSignature represents an aggregated signature
type AggregateSignature struct {
	point *blst.P2Affine
}

// GenerateKey generates a new random secret key
func GenerateKey() (*SecretKey, error) {
	ikm := make([]byte, 32)
	if _, err := rand.Read(ikm); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return GenerateKeyFromSeed(ikm)
}

// GenerateKeyFromSeed generates a secret key from a seed
func GenerateKeyFromSeed(seed []byte) (*SecretKey, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed must be at least 32 bytes")
	}
	sk := blst.KeyGen(seed)
	return &SecretKey{scalar: sk}, nil
}

// GetPublicKey derives the public key from a secret key
func (sk *SecretKey) GetPublicKey() *PublicKey {
	if sk == nil || sk.scalar == nil {
		return nil
	}
	pk := new(blst.P1Affine)
	pk.From(sk.scalar)
	return &PublicKey{point: pk}
}

// Sign signs a message with the secret key
func (sk *SecretKey) Sign(message []byte, dst []byte) (*Signature, error) {
	if sk == nil || sk.scalar == nil {
		return nil, fmt.Errorf("invalid secret key")
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}

	sig := new(blst.P2Affine)
	sig.Sign(sk.scalar, message, dst)
	return &Signature{point: sig}, nil
}

// Verify verifies a signature against a public key and message
func (pk *PublicKey) Verify(message []byte, signature *Signature, dst []byte) bool {
	if pk == nil || pk.point == nil || signature == nil || signature.point == nil {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}

	return signature.point.Verify(true, pk.point, true, message, dst)
}

// FastAggregateVerify verifies an aggregated signature for the same message
func FastAggregateVerify(pubkeys []*PublicKey, message []byte, signature *Signature, dst []byte) bool {
	if len(pubkeys) == 0 || signature == nil || signature.point == nil {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}

	// Convert public keys to blst format
	blstPubkeys := make([]*blst.P1Affine, len(pubkeys))
	for i, pk := range pubkeys {
		if pk == nil || pk.point == nil {
			return false
		}
		blstPubkeys[i] = pk.point
	}

	return signature.point.FastAggregateVerify(true, blstPubkeys, message, dst)
}

// AggregateVerify verifies an aggregated signature for different messages
func AggregateVerify(pubkeys []*PublicKey, messages [][]byte, signature *Signature, dst []byte) bool {
	if len(pubkeys) == 0 || len(pubkeys) != len(messages) || signature == nil {
		return false
	}
	if dst == nil {
		dst = []byte(DefaultDST)
	}

	// Convert public keys to blst format
	blstPubkeys := make([]*blst.P1Affine, len(pubkeys))
	for i, pk := range pubkeys {
		if pk == nil || pk.point == nil {
			return false
		}
		blstPubkeys[i] = pk.point
	}

	return signature.point.AggregateVerify(true, blstPubkeys, true, messages, dst)
}

// AggregatePubKeys aggregates multiple public keys
func AggregatePubKeys(pubkeys []*PublicKey) (*AggregatePublicKey, error) {
	if len(pubkeys) == 0 {
		return nil, ErrEmptyInput
	}

	// Start with first key
	if pubkeys[0] == nil || pubkeys[0].point == nil {
		return nil, ErrInvalidPublicKey
	}

	agg := new(blst.P1Aggregate)
	agg.Add(pubkeys[0].point, true)

	// Add remaining keys
	for i := 1; i < len(pubkeys); i++ {
		if pubkeys[i] == nil || pubkeys[i].point == nil {
			return nil, ErrInvalidPublicKey
		}
		agg.Add(pubkeys[i].point, true)
	}

	result := agg.ToAffine()
	return &AggregatePublicKey{point: result}, nil
}

// AggregateSignatures aggregates multiple signatures
func AggregateSignatures(signatures []*Signature) (*AggregateSignature, error) {
	if len(signatures) == 0 {
		return nil, ErrEmptyInput
	}

	// Start with first signature
	if signatures[0] == nil || signatures[0].point == nil {
		return nil, ErrInvalidSignature
	}

	agg := new(blst.P2Aggregate)
	agg.Add(signatures[0].point, true)

	// Add remaining signatures
	for i := 1; i < len(signatures); i++ {
		if signatures[i] == nil || signatures[i].point == nil {
			return nil, ErrInvalidSignature
		}
		agg.Add(signatures[i].point, true)
	}

	result := agg.ToAffine()
	return &AggregateSignature{point: result}, nil
}

// Serialize methods

// Serialize serializes a public key to compressed format
func (pk *PublicKey) Serialize() []byte {
	if pk == nil || pk.point == nil {
		return nil
	}
	return pk.point.Compress()
}

// Deserialize deserializes a public key from compressed format
func (pk *PublicKey) Deserialize(data []byte) error {
	point := new(blst.P1Affine)
	p1 := point.Uncompress(data)
	if p1 == nil {
		return ErrInvalidPublicKey
	}
	if !point.InG1() {
		return ErrInvalidPublicKey
	}
	pk.point = point
	return nil
}

// Serialize serializes a signature to compressed format
func (sig *Signature) Serialize() []byte {
	if sig == nil || sig.point == nil {
		return nil
	}
	return sig.point.Compress()
}

// Deserialize deserializes a signature from compressed format
func (sig *Signature) Deserialize(data []byte) error {
	point := new(blst.P2Affine)
	p2 := point.Uncompress(data)
	if p2 == nil {
		return ErrInvalidSignature
	}
	if !point.InG2() {
		return ErrInvalidSignature
	}
	sig.point = point
	return nil
}

// Serialize serializes a secret key
func (sk *SecretKey) Serialize() []byte {
	if sk == nil || sk.scalar == nil {
		return nil
	}
	return sk.scalar.Serialize()
}

// Deserialize deserializes a secret key
func (sk *SecretKey) Deserialize(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid secret key length: expected 32, got %d", len(data))
	}
	scalar := new(blst.SecretKey)
	scalar.Deserialize(data)
	sk.scalar = scalar
	return nil
}

// Batch verification for improved performance

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

	// For batch verification, we can use individual verification
	// TODO: Implement proper batch verification with pairing accumulation
	for i := range pubkeys {
		if !pubkeys[i].Verify(messages[i], signatures[i], dst) {
			return false
		}
	}

	return true
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
	return pk.point.Equals(other.point)
}

// Equal checks if two signatures are equal
func (sig *Signature) Equal(other *Signature) bool {
	if sig == nil || other == nil {
		return sig == other
	}
	if sig.point == nil || other.point == nil {
		return sig.point == other.point
	}
	return sig.point.Equals(other.point)
}
