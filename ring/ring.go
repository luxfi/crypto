// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ring implements ring signatures for anonymous group signing.
//
// Ring signatures allow a member of a group to sign a message such that it can
// be verified as coming from someone in the group, but without revealing which
// member actually signed. This provides strong anonymity guarantees.
//
// This package provides:
//   - LSAG (Linkable Spontaneous Anonymous Group) signatures using secp256k1
//   - Post-quantum ring signatures using lattice-based cryptography
//   - Key image support for linkability (double-spend prevention)
//
// For Q-Chain, ring signatures enable private transactions where the sender's
// identity is hidden among a set of possible signers (the "ring").
package ring

import (
	"crypto/rand"
	"errors"
	"io"
)

// Signature scheme types
type Scheme int

const (
	// LSAG is the Linkable Spontaneous Anonymous Group signature scheme
	// based on secp256k1 elliptic curves.
	LSAG Scheme = iota

	// LatticeLSAG is a post-quantum linkable ring signature scheme
	// based on Module-LWE lattices.
	LatticeLSAG

	// DualRing is an efficient ring signature construction.
	DualRing
)

// String returns the string representation of the scheme.
func (s Scheme) String() string {
	switch s {
	case LSAG:
		return "LSAG"
	case LatticeLSAG:
		return "Lattice-LSAG"
	case DualRing:
		return "DualRing"
	default:
		return "unknown"
	}
}

var (
	// ErrInvalidRingSize is returned when the ring size is invalid.
	ErrInvalidRingSize = errors.New("invalid ring size: must be at least 2")

	// ErrInvalidSignerIndex is returned when the signer index is out of bounds.
	ErrInvalidSignerIndex = errors.New("signer index out of bounds")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid ring signature")

	// ErrInvalidKeyImage is returned when the key image is invalid.
	ErrInvalidKeyImage = errors.New("invalid key image")

	// ErrKeyImageReused is returned when a key image has been used before.
	ErrKeyImageReused = errors.New("key image has been used (double spend detected)")

	// ErrInvalidPublicKey is returned when a public key is invalid.
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidPrivateKey is returned when a private key is invalid.
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrRingSizeMismatch is returned when signature ring size doesn't match.
	ErrRingSizeMismatch = errors.New("ring size mismatch")
)

// RingSignature represents a ring signature that can be verified against
// a ring of public keys without revealing which key created it.
type RingSignature interface {
	// Scheme returns the signature scheme used.
	Scheme() Scheme

	// Bytes serializes the signature to bytes.
	Bytes() []byte

	// KeyImage returns the key image for linkability.
	// Two signatures from the same private key will have the same key image.
	KeyImage() []byte

	// RingSize returns the number of public keys in the ring.
	RingSize() int

	// Verify verifies the signature against the given message and ring.
	Verify(message []byte, ring [][]byte) bool
}

// Signer creates ring signatures.
type Signer interface {
	// Scheme returns the signature scheme used.
	Scheme() Scheme

	// PublicKey returns the signer's public key.
	PublicKey() []byte

	// Sign creates a ring signature for the given message.
	// The signer's public key must be included in the ring at signerIndex.
	Sign(message []byte, ring [][]byte, signerIndex int) (RingSignature, error)

	// KeyImage returns the key image derived from this signer's private key.
	KeyImage() []byte
}

// ParseSignature parses a ring signature from bytes.
func ParseSignature(scheme Scheme, data []byte) (RingSignature, error) {
	switch scheme {
	case LSAG:
		return ParseLSAGSignature(data)
	case LatticeLSAG:
		return ParseLatticeSignature(data)
	default:
		return nil, errors.New("unsupported signature scheme")
	}
}

// NewSigner creates a new ring signer with a random private key.
func NewSigner(scheme Scheme) (Signer, error) {
	return NewSignerFromReader(scheme, rand.Reader)
}

// NewSignerFromReader creates a new ring signer using the given random source.
func NewSignerFromReader(scheme Scheme, reader io.Reader) (Signer, error) {
	switch scheme {
	case LSAG:
		return NewLSAGSigner(reader)
	case LatticeLSAG:
		return NewLatticeSigner(reader)
	default:
		return nil, errors.New("unsupported signature scheme")
	}
}

// NewSignerFromPrivateKey creates a signer from an existing private key.
func NewSignerFromPrivateKey(scheme Scheme, privateKey []byte) (Signer, error) {
	switch scheme {
	case LSAG:
		return NewLSAGSignerFromPrivateKey(privateKey)
	case LatticeLSAG:
		return NewLatticeSignerFromPrivateKey(privateKey)
	default:
		return nil, errors.New("unsupported signature scheme")
	}
}

// GenerateRing generates a ring of random public keys for testing/demo purposes.
// In production, the ring should consist of real public keys from the network.
func GenerateRing(scheme Scheme, size int) ([][]byte, error) {
	if size < 2 {
		return nil, ErrInvalidRingSize
	}

	ring := make([][]byte, size)
	for i := 0; i < size; i++ {
		signer, err := NewSigner(scheme)
		if err != nil {
			return nil, err
		}
		ring[i] = signer.PublicKey()
	}

	return ring, nil
}

// KeyImageStore tracks used key images for double-spend detection.
type KeyImageStore interface {
	// HasKeyImage checks if a key image has been used.
	HasKeyImage(keyImage []byte) bool

	// AddKeyImage records a key image as used.
	AddKeyImage(keyImage []byte) error

	// RemoveKeyImage removes a key image (for rollback).
	RemoveKeyImage(keyImage []byte) error
}

// MemoryKeyImageStore is an in-memory implementation of KeyImageStore.
type MemoryKeyImageStore struct {
	images map[string]struct{}
}

// NewMemoryKeyImageStore creates a new in-memory key image store.
func NewMemoryKeyImageStore() *MemoryKeyImageStore {
	return &MemoryKeyImageStore{
		images: make(map[string]struct{}),
	}
}

// HasKeyImage checks if a key image has been used.
func (s *MemoryKeyImageStore) HasKeyImage(keyImage []byte) bool {
	_, exists := s.images[string(keyImage)]
	return exists
}

// AddKeyImage records a key image as used.
func (s *MemoryKeyImageStore) AddKeyImage(keyImage []byte) error {
	if s.HasKeyImage(keyImage) {
		return ErrKeyImageReused
	}
	s.images[string(keyImage)] = struct{}{}
	return nil
}

// RemoveKeyImage removes a key image.
func (s *MemoryKeyImageStore) RemoveKeyImage(keyImage []byte) error {
	delete(s.images, string(keyImage))
	return nil
}

// VerifyAndRecord verifies a ring signature and records its key image.
// Returns an error if verification fails or if the key image was already used.
func VerifyAndRecord(sig RingSignature, message []byte, ring [][]byte, store KeyImageStore) error {
	// Check for double-spend first
	keyImage := sig.KeyImage()
	if store.HasKeyImage(keyImage) {
		return ErrKeyImageReused
	}

	// Verify signature
	if !sig.Verify(message, ring) {
		return ErrInvalidSignature
	}

	// Record key image
	return store.AddKeyImage(keyImage)
}

// constantTimeCompare compares two byte slices in constant time to prevent timing attacks.
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
