// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package threshold defines interfaces for threshold signature schemes.
//
// This package provides a unified interface layer for multiple threshold signature
// implementations including:
//   - FROST (Flexible Round-Optimized Schnorr Threshold)
//   - CMP/CGGMP21 (Threshold ECDSA)
//   - BLS Threshold (Boneh-Lynn-Shacham)
//   - Ringtail (Lattice-based threshold, post-quantum)
//
// The interfaces are designed to support both interactive (multi-round) and
// non-interactive threshold signing protocols.
//
// Usage:
//
//	scheme, err := threshold.GetScheme(threshold.SchemeFROST)
//	if err != nil {
//	    return err
//	}
//
//	// Distributed key generation
//	dkg := scheme.NewDKG(config)
//	keyShare, err := dkg.Generate(ctx, participants)
//
//	// Signing
//	signer := scheme.NewSigner(keyShare)
//	share, err := signer.SignShare(ctx, message)
//
//	// Aggregation
//	aggregator := scheme.NewAggregator(groupKey)
//	signature, err := aggregator.Aggregate(ctx, shares)
package threshold

import (
	"context"
	"io"
)

// SchemeID identifies a threshold signature scheme.
type SchemeID uint8

const (
	// SchemeUnknown represents an unknown or uninitialized scheme.
	SchemeUnknown SchemeID = iota

	// SchemeFROST is the Flexible Round-Optimized Schnorr Threshold scheme.
	// Produces Schnorr signatures compatible with Ed25519/EdDSA.
	SchemeFROST

	// SchemeCMP is the Canetti-Makriyannis-Pagourtzis threshold ECDSA scheme.
	// Also known as CGGMP21 in its updated form.
	SchemeCMP

	// SchemeBLS is the BLS threshold signature scheme.
	// Supports non-interactive aggregation.
	SchemeBLS

	// SchemeRingtail is the lattice-based threshold signature scheme.
	// Provides post-quantum security.
	SchemeRingtail
)

// String returns the string representation of the scheme ID.
func (s SchemeID) String() string {
	switch s {
	case SchemeFROST:
		return "FROST"
	case SchemeCMP:
		return "CMP"
	case SchemeBLS:
		return "BLS"
	case SchemeRingtail:
		return "Ringtail"
	default:
		return "Unknown"
	}
}

// IsPostQuantum returns true if the scheme provides post-quantum security.
func (s SchemeID) IsPostQuantum() bool {
	return s == SchemeRingtail
}

// SupportsNonInteractive returns true if shares can be aggregated without
// additional communication rounds.
func (s SchemeID) SupportsNonInteractive() bool {
	return s == SchemeBLS
}

// Scheme represents a threshold signature scheme.
// It serves as the factory for creating DKG, Signer, and Aggregator instances.
type Scheme interface {
	// ID returns the unique identifier for this scheme.
	ID() SchemeID

	// Name returns a human-readable name for the scheme.
	Name() string

	// KeyShareSize returns the serialized size of a key share in bytes.
	KeyShareSize() int

	// SignatureShareSize returns the serialized size of a signature share in bytes.
	SignatureShareSize() int

	// SignatureSize returns the serialized size of the final signature in bytes.
	SignatureSize() int

	// PublicKeySize returns the serialized size of the group public key in bytes.
	PublicKeySize() int

	// NewDKG creates a new distributed key generation instance.
	NewDKG(config DKGConfig) (DKG, error)

	// NewTrustedDealer creates a trusted dealer for centralized key generation.
	// Returns an error if the scheme doesn't support trusted dealer setup.
	NewTrustedDealer(config DealerConfig) (TrustedDealer, error)

	// NewSigner creates a signer from a key share.
	NewSigner(share KeyShare) (Signer, error)

	// NewAggregator creates a signature aggregator for the given group key.
	NewAggregator(groupKey PublicKey) (Aggregator, error)

	// NewVerifier creates a signature verifier for the given group key.
	NewVerifier(groupKey PublicKey) (Verifier, error)

	// ParseKeyShare deserializes a key share from bytes.
	ParseKeyShare(data []byte) (KeyShare, error)

	// ParsePublicKey deserializes a group public key from bytes.
	ParsePublicKey(data []byte) (PublicKey, error)

	// ParseSignatureShare deserializes a signature share from bytes.
	ParseSignatureShare(data []byte) (SignatureShare, error)

	// ParseSignature deserializes a final signature from bytes.
	ParseSignature(data []byte) (Signature, error)
}

// DKGConfig contains configuration for distributed key generation.
type DKGConfig struct {
	// Threshold is the minimum number of parties required to sign (t).
	// A valid signature requires at least Threshold+1 shares.
	Threshold int

	// TotalParties is the total number of parties (n).
	TotalParties int

	// PartyIndex is this party's index (0 to TotalParties-1).
	PartyIndex int

	// PartyID is an optional identifier for this party.
	PartyID []byte

	// Randomness source (defaults to crypto/rand if nil).
	Rand io.Reader
}

// Validate checks if the DKG configuration is valid.
func (c DKGConfig) Validate() error {
	if c.Threshold < 1 {
		return ErrInvalidThreshold
	}
	if c.TotalParties < 2 {
		return ErrInvalidPartyCount
	}
	if c.Threshold >= c.TotalParties {
		return ErrThresholdTooHigh
	}
	if c.PartyIndex < 0 || c.PartyIndex >= c.TotalParties {
		return ErrInvalidPartyIndex
	}
	return nil
}

// DealerConfig contains configuration for trusted dealer key generation.
type DealerConfig struct {
	// Threshold is the minimum number of parties required to sign.
	Threshold int

	// TotalParties is the total number of parties.
	TotalParties int

	// Randomness source (defaults to crypto/rand if nil).
	Rand io.Reader
}

// Validate checks if the dealer configuration is valid.
func (c DealerConfig) Validate() error {
	if c.Threshold < 1 {
		return ErrInvalidThreshold
	}
	if c.TotalParties < 2 {
		return ErrInvalidPartyCount
	}
	if c.Threshold >= c.TotalParties {
		return ErrThresholdTooHigh
	}
	return nil
}

// DKG represents a distributed key generation protocol.
// The protocol proceeds in multiple rounds, with each round producing
// messages to broadcast and processing received messages.
type DKG interface {
	// Round1 generates the first round message to broadcast.
	// Returns the message to send to all other parties.
	Round1(ctx context.Context) (DKGMessage, error)

	// Round2 processes Round1 messages and generates Round2 messages.
	// The input map is keyed by party index.
	Round2(ctx context.Context, round1Messages map[int]DKGMessage) (DKGMessage, error)

	// Round3 processes Round2 messages and generates the final key share.
	// Some schemes may not require Round3; they return the key share from Round2.
	Round3(ctx context.Context, round2Messages map[int]DKGMessage) (KeyShare, error)

	// NumRounds returns the number of rounds required for this DKG protocol.
	NumRounds() int

	// GroupKey returns the group public key after DKG completes.
	// Returns nil if DKG has not completed.
	GroupKey() PublicKey
}

// TrustedDealer generates key shares in a centralized manner.
// This is simpler than DKG but requires trusting the dealer.
type TrustedDealer interface {
	// GenerateShares creates all key shares and the group public key.
	// Returns a slice of key shares (indexed 0 to n-1) and the group key.
	GenerateShares(ctx context.Context) ([]KeyShare, PublicKey, error)
}

// DKGMessage represents a message in the DKG protocol.
type DKGMessage interface {
	// Round returns which round this message belongs to.
	Round() int

	// FromParty returns the index of the party that created this message.
	FromParty() int

	// Bytes serializes the message for transmission.
	Bytes() []byte
}

// KeyShare represents a party's share of the threshold key.
type KeyShare interface {
	// Index returns the party index for this share.
	Index() int

	// GroupKey returns the group public key.
	GroupKey() PublicKey

	// PublicShare returns this party's public key share.
	// This can be used for share verification.
	PublicShare() []byte

	// Threshold returns the signing threshold.
	Threshold() int

	// TotalParties returns the total number of parties.
	TotalParties() int

	// Bytes serializes the key share.
	Bytes() []byte

	// SchemeID returns the scheme this share belongs to.
	SchemeID() SchemeID
}

// PublicKey represents the threshold group public key.
type PublicKey interface {
	// Bytes serializes the public key.
	Bytes() []byte

	// Equal returns true if the public keys are identical.
	Equal(other PublicKey) bool

	// SchemeID returns the scheme this key belongs to.
	SchemeID() SchemeID
}

// Signer creates signature shares for a threshold signing protocol.
type Signer interface {
	// Index returns the party index for this signer.
	Index() int

	// PublicShare returns this party's public key share.
	PublicShare() []byte

	// NonceGen generates a nonce commitment for signing.
	// Returns a commitment to broadcast and nonce state to preserve.
	// Not all schemes require this step.
	NonceGen(ctx context.Context) (NonceCommitment, NonceState, error)

	// SignShare creates a signature share for the given message.
	// For multi-round schemes, this may require nonce state from NonceGen.
	// The signers parameter contains the indices of all participating signers.
	SignShare(ctx context.Context, message []byte, signers []int, nonce NonceState) (SignatureShare, error)

	// KeyShare returns the underlying key share.
	KeyShare() KeyShare
}

// NonceCommitment represents a commitment to a signing nonce.
// Used in schemes like FROST that require nonce pre-generation.
type NonceCommitment interface {
	// Bytes serializes the commitment.
	Bytes() []byte

	// FromParty returns the index of the party that created this commitment.
	FromParty() int
}

// NonceState represents the secret nonce state for signing.
// This must be kept secret and used exactly once.
type NonceState interface {
	// Bytes serializes the nonce state (for secure storage).
	Bytes() []byte

	// FromParty returns the index of the party that owns this nonce.
	FromParty() int
}

// SignatureShare represents a party's share of a threshold signature.
type SignatureShare interface {
	// Index returns the party index that created this share.
	Index() int

	// Bytes serializes the signature share.
	Bytes() []byte

	// SchemeID returns the scheme this share belongs to.
	SchemeID() SchemeID
}

// Aggregator combines signature shares into a final signature.
type Aggregator interface {
	// Aggregate combines signature shares into a final signature.
	// For non-interactive schemes (BLS), this combines shares directly.
	// For interactive schemes, commitments from all signers may be required.
	Aggregate(ctx context.Context, message []byte, shares []SignatureShare, commitments []NonceCommitment) (Signature, error)

	// VerifyShare verifies a single signature share before aggregation.
	// Returns nil if the share is valid.
	VerifyShare(message []byte, share SignatureShare, publicShare []byte) error

	// GroupKey returns the group public key for this aggregator.
	GroupKey() PublicKey
}

// Signature represents a complete threshold signature.
type Signature interface {
	// Bytes serializes the signature.
	Bytes() []byte

	// SchemeID returns the scheme that produced this signature.
	SchemeID() SchemeID
}

// Verifier verifies threshold signatures.
type Verifier interface {
	// Verify checks if a signature is valid for the given message.
	Verify(message []byte, signature Signature) bool

	// VerifyBytes verifies a serialized signature.
	VerifyBytes(message, signature []byte) bool

	// GroupKey returns the group public key for this verifier.
	GroupKey() PublicKey
}

// KeyRefresh provides key share refresh functionality.
// This allows updating shares while keeping the same group key.
type KeyRefresh interface {
	// Round1 generates the first round of key refresh messages.
	Round1(ctx context.Context) (DKGMessage, error)

	// Round2 processes Round1 messages and generates new shares.
	Round2(ctx context.Context, round1Messages map[int]DKGMessage) (KeyShare, error)
}

// Resharing provides proactive share update with threshold change.
type Resharing interface {
	// GenerateReshareMessages creates messages for resharing to new parties.
	GenerateReshareMessages(ctx context.Context, newThreshold, newTotal int) ([]DKGMessage, error)

	// ProcessReshareMessages processes reshare messages to create a new share.
	ProcessReshareMessages(ctx context.Context, messages []DKGMessage) (KeyShare, error)
}
