// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import "errors"

// Sentinel errors for threshold signature operations.
var (
	// Configuration errors
	ErrInvalidThreshold   = errors.New("threshold: invalid threshold value")
	ErrInvalidPartyCount  = errors.New("threshold: invalid party count")
	ErrThresholdTooHigh   = errors.New("threshold: threshold must be less than total parties")
	ErrInvalidPartyIndex  = errors.New("threshold: party index out of range")
	ErrInvalidConfig      = errors.New("threshold: invalid configuration")

	// Scheme errors
	ErrSchemeNotFound     = errors.New("threshold: scheme not registered")
	ErrSchemeNotSupported = errors.New("threshold: operation not supported by scheme")

	// Key errors
	ErrInvalidKeyShare     = errors.New("threshold: invalid key share")
	ErrInvalidPublicKey    = errors.New("threshold: invalid public key")
	ErrKeyShareMismatch    = errors.New("threshold: key share does not match group key")
	ErrDuplicateKeyShare   = errors.New("threshold: duplicate key share index")
	ErrInsufficientShares  = errors.New("threshold: insufficient shares for threshold")
	ErrKeyShareCorrupted   = errors.New("threshold: key share data corrupted")

	// Signature errors
	ErrInvalidSignatureShare = errors.New("threshold: invalid signature share")
	ErrInvalidSignature      = errors.New("threshold: invalid signature")
	ErrSignatureShareMismatch = errors.New("threshold: signature share does not match")
	ErrDuplicateSignatureShare = errors.New("threshold: duplicate signature share index")
	ErrSignatureVerificationFailed = errors.New("threshold: signature verification failed")

	// Protocol errors
	ErrProtocolAborted       = errors.New("threshold: protocol aborted")
	ErrInvalidRound          = errors.New("threshold: invalid protocol round")
	ErrMissingMessage        = errors.New("threshold: missing message from party")
	ErrInvalidMessage        = errors.New("threshold: invalid protocol message")
	ErrMessageFromWrongParty = errors.New("threshold: message from unexpected party")
	ErrMessageFromSelf       = errors.New("threshold: cannot process own message")

	// Nonce errors
	ErrNonceReused     = errors.New("threshold: nonce already used")
	ErrNonceMissing    = errors.New("threshold: nonce state required")
	ErrInvalidNonce    = errors.New("threshold: invalid nonce")
	ErrNonceCommitmentMismatch = errors.New("threshold: nonce commitment mismatch")

	// State errors
	ErrNotInitialized = errors.New("threshold: not initialized")
	ErrAlreadyComplete = errors.New("threshold: operation already complete")
	ErrInvalidState   = errors.New("threshold: invalid state for operation")

	// Serialization errors
	ErrInvalidEncoding = errors.New("threshold: invalid encoding")
	ErrDataTooShort    = errors.New("threshold: data too short")
	ErrDataTooLong     = errors.New("threshold: data too long")
	ErrVersionMismatch = errors.New("threshold: version mismatch")
)

// IdentifiableAbortError contains information about a misbehaving party.
// Schemes with identifiable abort can return this error to identify
// which party caused the protocol to fail.
type IdentifiableAbortError struct {
	// PartyIndex is the index of the misbehaving party.
	PartyIndex int

	// Round is the protocol round where misbehavior was detected.
	Round int

	// Reason describes the misbehavior.
	Reason string

	// Proof contains cryptographic proof of misbehavior (scheme-specific).
	Proof []byte
}

func (e *IdentifiableAbortError) Error() string {
	return "threshold: identifiable abort - party " + string(rune(e.PartyIndex+'0')) + " misbehaved in round " + string(rune(e.Round+'0')) + ": " + e.Reason
}

// IsIdentifiableAbort returns true if the error is an identifiable abort.
func IsIdentifiableAbort(err error) bool {
	var abortErr *IdentifiableAbortError
	return errors.As(err, &abortErr)
}

// GetAbortingParty returns the party index from an identifiable abort error.
// Returns -1 if the error is not an identifiable abort.
func GetAbortingParty(err error) int {
	var abortErr *IdentifiableAbortError
	if errors.As(err, &abortErr) {
		return abortErr.PartyIndex
	}
	return -1
}

// ShareError wraps an error with share index information.
type ShareError struct {
	Index int
	Err   error
}

func (e *ShareError) Error() string {
	return "threshold: share " + string(rune(e.Index+'0')) + ": " + e.Err.Error()
}

func (e *ShareError) Unwrap() error {
	return e.Err
}
