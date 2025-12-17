// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Hybrid signer combining BLS and threshold signatures for Lux consensus

package signer

import (
	"context"
	"crypto/rand"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/threshold"
)

// Signer provides BLS signing for Lux consensus.
// Threshold signing is coordinated through the consensus layer
// using github.com/luxfi/threshold protocols.
type Signer struct {
	blsKey *bls.SecretKey

	// Threshold key seed for participation in threshold protocols
	// Actual threshold operations are in github.com/luxfi/threshold
	thresholdSeed []byte

	// thresholdAdapter provides threshold signing when a key share is set
	thresholdAdapter *threshold.SchemeAdapter
}

// NewSigner creates a signer with BLS key and threshold seed
func NewSigner() (*Signer, error) {
	// Generate BLS key
	blsKey, err := bls.NewSecretKey()
	if err != nil {
		return nil, err
	}

	// Generate threshold seed (used to derive keys for threshold protocols)
	thresholdSeed := make([]byte, 32)
	if _, err := rand.Read(thresholdSeed); err != nil {
		return nil, err
	}

	return &Signer{
		blsKey:        blsKey,
		thresholdSeed: thresholdSeed,
	}, nil
}

// NewSignerWithThreshold creates a signer with a threshold key share.
func NewSignerWithThreshold(keyShare threshold.KeyShare) (*Signer, error) {
	// Create threshold adapter
	adapter, err := threshold.NewAdapter(keyShare)
	if err != nil {
		return nil, err
	}

	// Generate BLS key
	blsKey, err := bls.NewSecretKey()
	if err != nil {
		return nil, err
	}

	// Generate threshold seed
	thresholdSeed := make([]byte, 32)
	if _, err := rand.Read(thresholdSeed); err != nil {
		return nil, err
	}

	return &Signer{
		blsKey:           blsKey,
		thresholdSeed:    thresholdSeed,
		thresholdAdapter: adapter,
	}, nil
}

// SetThresholdKeyShare sets the threshold key share for this signer.
func (s *Signer) SetThresholdKeyShare(keyShare threshold.KeyShare) error {
	adapter, err := threshold.NewAdapter(keyShare)
	if err != nil {
		return err
	}
	s.thresholdAdapter = adapter
	return nil
}

// SignBLS creates a BLS signature
func (s *Signer) SignBLS(message []byte) ([]byte, error) {
	sig, err := s.blsKey.Sign(message)
	if err != nil {
		return nil, err
	}
	return bls.SignatureToBytes(sig), nil
}

// VerifyBLS verifies a BLS signature
func (s *Signer) VerifyBLS(message, signature []byte) bool {
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return false
	}
	pubKey := s.blsKey.PublicKey()
	return bls.Verify(pubKey, sig, message)
}

// GetBLSPublicKey returns the BLS public key bytes
func (s *Signer) GetBLSPublicKey() []byte {
	pubKey := s.blsKey.PublicKey()
	return bls.PublicKeyToCompressedBytes(pubKey)
}

// BLSSecretKey returns the underlying BLS secret key for advanced operations
func (s *Signer) BLSSecretKey() *bls.SecretKey {
	return s.blsKey
}

// ThresholdSeed returns the seed for threshold protocol key derivation.
// Use with github.com/luxfi/threshold to participate in threshold signing.
func (s *Signer) ThresholdSeed() []byte {
	return s.thresholdSeed
}

// HasThresholdKey returns true if this signer has a threshold key share.
func (s *Signer) HasThresholdKey() bool {
	return s.thresholdAdapter != nil
}

// ThresholdSchemeID returns the threshold scheme ID if a key share is set.
// Returns SchemeUnknown if no threshold key is configured.
func (s *Signer) ThresholdSchemeID() threshold.SchemeID {
	if s.thresholdAdapter == nil {
		return threshold.SchemeUnknown
	}
	return s.thresholdAdapter.SchemeID()
}

// ThresholdIndex returns this signer's index in the threshold scheme.
// Returns -1 if no threshold key is configured.
func (s *Signer) ThresholdIndex() int {
	if s.thresholdAdapter == nil {
		return -1
	}
	return s.thresholdAdapter.Index()
}

// ThresholdPublicShare returns this signer's public key share.
// Returns nil if no threshold key is configured.
func (s *Signer) ThresholdPublicShare() []byte {
	if s.thresholdAdapter == nil {
		return nil
	}
	return s.thresholdAdapter.PublicShare()
}

// ThresholdGroupKey returns the threshold group public key.
// Returns nil if no threshold key is configured.
func (s *Signer) ThresholdGroupKey() threshold.PublicKey {
	if s.thresholdAdapter == nil {
		return nil
	}
	return s.thresholdAdapter.GroupKey()
}

// SignThresholdShare creates a threshold signature share for the given message.
// The signers parameter contains the indices of all parties participating in this signing.
// Returns an error if no threshold key is configured.
func (s *Signer) SignThresholdShare(ctx context.Context, message []byte, signers []int) (threshold.SignatureShare, error) {
	if s.thresholdAdapter == nil {
		return nil, threshold.ErrNotInitialized
	}
	return s.thresholdAdapter.SignShare(ctx, message, signers)
}

// AggregateThresholdShares combines signature shares into a final signature.
// Returns an error if no threshold key is configured.
func (s *Signer) AggregateThresholdShares(ctx context.Context, message []byte, shares []threshold.SignatureShare) (threshold.Signature, error) {
	if s.thresholdAdapter == nil {
		return nil, threshold.ErrNotInitialized
	}
	return s.thresholdAdapter.Aggregate(ctx, message, shares)
}

// VerifyThresholdShare verifies a single signature share.
// Returns an error if no threshold key is configured or the share is invalid.
func (s *Signer) VerifyThresholdShare(message []byte, share threshold.SignatureShare, publicShare []byte) error {
	if s.thresholdAdapter == nil {
		return threshold.ErrNotInitialized
	}
	return s.thresholdAdapter.VerifyShare(message, share, publicShare)
}

// VerifyThreshold verifies a complete threshold signature.
// Returns false if no threshold key is configured.
func (s *Signer) VerifyThreshold(message []byte, signature threshold.Signature) bool {
	if s.thresholdAdapter == nil {
		return false
	}
	return s.thresholdAdapter.Verify(message, signature)
}

// VerifyThresholdBytes verifies a serialized threshold signature.
// Returns false if no threshold key is configured.
func (s *Signer) VerifyThresholdBytes(message, signature []byte) bool {
	if s.thresholdAdapter == nil {
		return false
	}
	return s.thresholdAdapter.VerifyBytes(message, signature)
}
