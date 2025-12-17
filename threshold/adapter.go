// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"context"
)

// SchemeAdapter provides a simplified interface for using threshold schemes.
// It wraps the full scheme interfaces for common use cases.
type SchemeAdapter struct {
	scheme    Scheme
	keyShare  KeyShare
	signer    Signer
	verifier  Verifier
	aggregator Aggregator
}

// NewAdapter creates a new scheme adapter from a key share.
func NewAdapter(share KeyShare) (*SchemeAdapter, error) {
	scheme, err := GetScheme(share.SchemeID())
	if err != nil {
		return nil, err
	}

	signer, err := scheme.NewSigner(share)
	if err != nil {
		return nil, err
	}

	aggregator, err := scheme.NewAggregator(share.GroupKey())
	if err != nil {
		return nil, err
	}

	verifier, err := scheme.NewVerifier(share.GroupKey())
	if err != nil {
		return nil, err
	}

	return &SchemeAdapter{
		scheme:     scheme,
		keyShare:   share,
		signer:     signer,
		verifier:   verifier,
		aggregator: aggregator,
	}, nil
}

// SignShare creates a signature share for the given message.
func (a *SchemeAdapter) SignShare(ctx context.Context, message []byte, signers []int) (SignatureShare, error) {
	return a.signer.SignShare(ctx, message, signers, nil)
}

// Aggregate combines signature shares into a final signature.
func (a *SchemeAdapter) Aggregate(ctx context.Context, message []byte, shares []SignatureShare) (Signature, error) {
	return a.aggregator.Aggregate(ctx, message, shares, nil)
}

// VerifyShare verifies a single signature share.
func (a *SchemeAdapter) VerifyShare(message []byte, share SignatureShare, publicShare []byte) error {
	return a.aggregator.VerifyShare(message, share, publicShare)
}

// Verify verifies a final signature.
func (a *SchemeAdapter) Verify(message []byte, signature Signature) bool {
	return a.verifier.Verify(message, signature)
}

// VerifyBytes verifies a serialized signature.
func (a *SchemeAdapter) VerifyBytes(message, signature []byte) bool {
	return a.verifier.VerifyBytes(message, signature)
}

// Index returns this party's index.
func (a *SchemeAdapter) Index() int {
	return a.keyShare.Index()
}

// PublicShare returns this party's public key share.
func (a *SchemeAdapter) PublicShare() []byte {
	return a.keyShare.PublicShare()
}

// GroupKey returns the group public key.
func (a *SchemeAdapter) GroupKey() PublicKey {
	return a.keyShare.GroupKey()
}

// Threshold returns the signing threshold.
func (a *SchemeAdapter) Threshold() int {
	return a.keyShare.Threshold()
}

// SchemeID returns the scheme identifier.
func (a *SchemeAdapter) SchemeID() SchemeID {
	return a.scheme.ID()
}

// QuickSign provides a one-shot threshold signing helper.
// It collects shares, aggregates them, and returns the final signature.
type QuickSign struct {
	scheme     Scheme
	groupKey   PublicKey
	threshold  int
	aggregator Aggregator
}

// NewQuickSign creates a new quick signing helper.
func NewQuickSign(schemeID SchemeID, groupKey PublicKey, threshold int) (*QuickSign, error) {
	scheme, err := GetScheme(schemeID)
	if err != nil {
		return nil, err
	}

	aggregator, err := scheme.NewAggregator(groupKey)
	if err != nil {
		return nil, err
	}

	return &QuickSign{
		scheme:     scheme,
		groupKey:   groupKey,
		threshold:  threshold,
		aggregator: aggregator,
	}, nil
}

// SignAndAggregate creates signature shares and aggregates them.
// This is a convenience method for when all signers are local.
func (q *QuickSign) SignAndAggregate(ctx context.Context, message []byte, signers []Signer) (Signature, error) {
	if len(signers) <= q.threshold {
		return nil, ErrInsufficientShares
	}

	// Collect signer indices
	indices := make([]int, len(signers))
	for i, s := range signers {
		indices[i] = s.Index()
	}

	// Generate signature shares
	shares := make([]SignatureShare, len(signers))
	for i, s := range signers {
		share, err := s.SignShare(ctx, message, indices, nil)
		if err != nil {
			return nil, &ShareError{Index: s.Index(), Err: err}
		}
		shares[i] = share
	}

	// Aggregate
	return q.aggregator.Aggregate(ctx, message, shares, nil)
}

// Verify verifies a signature.
func (q *QuickSign) Verify(message []byte, signature Signature) bool {
	verifier, err := q.scheme.NewVerifier(q.groupKey)
	if err != nil {
		return false
	}
	return verifier.Verify(message, signature)
}

// GroupKey returns the group public key.
func (q *QuickSign) GroupKey() PublicKey {
	return q.groupKey
}

// Threshold returns the signing threshold.
func (q *QuickSign) Threshold() int {
	return q.threshold
}
