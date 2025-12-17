// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"context"
	"sync"
	"time"
)

// SessionState represents the state of a threshold signing session.
type SessionState uint8

const (
	// SessionStateNew indicates a newly created session.
	SessionStateNew SessionState = iota

	// SessionStateNonceGeneration indicates nonce generation phase.
	SessionStateNonceGeneration

	// SessionStateSigning indicates signature share generation phase.
	SessionStateSigning

	// SessionStateAggregating indicates signature aggregation phase.
	SessionStateAggregating

	// SessionStateComplete indicates the session has completed successfully.
	SessionStateComplete

	// SessionStateFailed indicates the session has failed.
	SessionStateFailed
)

// String returns the string representation of the session state.
func (s SessionState) String() string {
	switch s {
	case SessionStateNew:
		return "New"
	case SessionStateNonceGeneration:
		return "NonceGeneration"
	case SessionStateSigning:
		return "Signing"
	case SessionStateAggregating:
		return "Aggregating"
	case SessionStateComplete:
		return "Complete"
	case SessionStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// SigningSession manages a multi-party threshold signing session.
// It tracks participants, collected shares, and session state.
type SigningSession struct {
	// ID is a unique identifier for this session.
	ID string

	// SchemeID identifies the threshold scheme being used.
	SchemeID SchemeID

	// Message is the message being signed.
	Message []byte

	// GroupKey is the threshold group public key.
	GroupKey PublicKey

	// Threshold is the minimum number of signers required.
	Threshold int

	// Participants contains the indices of parties participating in this session.
	Participants []int

	// Commitments stores nonce commitments from each participant.
	// Keyed by party index.
	Commitments map[int]NonceCommitment

	// Shares stores signature shares from each participant.
	// Keyed by party index.
	Shares map[int]SignatureShare

	// PublicShares stores public key shares for verification.
	// Keyed by party index.
	PublicShares map[int][]byte

	// State is the current session state.
	State SessionState

	// Result holds the final signature on success.
	Result Signature

	// Error holds the error if the session failed.
	Error error

	// CreatedAt is when the session was created.
	CreatedAt time.Time

	// UpdatedAt is when the session was last updated.
	UpdatedAt time.Time

	// Timeout is the session timeout duration.
	Timeout time.Duration

	mu sync.RWMutex
}

// NewSigningSession creates a new signing session.
func NewSigningSession(id string, scheme SchemeID, message []byte, groupKey PublicKey, threshold int, timeout time.Duration) *SigningSession {
	now := time.Now()
	return &SigningSession{
		ID:           id,
		SchemeID:     scheme,
		Message:      message,
		GroupKey:     groupKey,
		Threshold:    threshold,
		Participants: make([]int, 0),
		Commitments:  make(map[int]NonceCommitment),
		Shares:       make(map[int]SignatureShare),
		PublicShares: make(map[int][]byte),
		State:        SessionStateNew,
		CreatedAt:    now,
		UpdatedAt:    now,
		Timeout:      timeout,
	}
}

// AddParticipant adds a party to the session.
func (s *SigningSession) AddParticipant(index int, publicShare []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State != SessionStateNew {
		return ErrInvalidState
	}

	// Check for duplicate
	for _, p := range s.Participants {
		if p == index {
			return ErrDuplicateKeyShare
		}
	}

	s.Participants = append(s.Participants, index)
	s.PublicShares[index] = publicShare
	s.UpdatedAt = time.Now()
	return nil
}

// AddCommitment adds a nonce commitment from a participant.
func (s *SigningSession) AddCommitment(index int, commitment NonceCommitment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State != SessionStateNew && s.State != SessionStateNonceGeneration {
		return ErrInvalidState
	}

	if _, exists := s.Commitments[index]; exists {
		return ErrNonceReused
	}

	// Verify participant is in session
	found := false
	for _, p := range s.Participants {
		if p == index {
			found = true
			break
		}
	}
	if !found {
		return ErrMessageFromWrongParty
	}

	s.Commitments[index] = commitment
	s.State = SessionStateNonceGeneration
	s.UpdatedAt = time.Now()
	return nil
}

// AddShare adds a signature share from a participant.
func (s *SigningSession) AddShare(index int, share SignatureShare) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State != SessionStateNonceGeneration && s.State != SessionStateSigning {
		return ErrInvalidState
	}

	if _, exists := s.Shares[index]; exists {
		return ErrDuplicateSignatureShare
	}

	// Verify participant is in session
	found := false
	for _, p := range s.Participants {
		if p == index {
			found = true
			break
		}
	}
	if !found {
		return ErrMessageFromWrongParty
	}

	s.Shares[index] = share
	s.State = SessionStateSigning
	s.UpdatedAt = time.Now()
	return nil
}

// HasEnoughShares returns true if enough shares have been collected.
func (s *SigningSession) HasEnoughShares() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.Shares) >= s.Threshold+1
}

// HasEnoughCommitments returns true if enough commitments have been collected.
func (s *SigningSession) HasEnoughCommitments() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.Commitments) >= s.Threshold+1
}

// GetShares returns all collected signature shares.
func (s *SigningSession) GetShares() []SignatureShare {
	s.mu.RLock()
	defer s.mu.RUnlock()

	shares := make([]SignatureShare, 0, len(s.Shares))
	for _, share := range s.Shares {
		shares = append(shares, share)
	}
	return shares
}

// GetCommitments returns all collected nonce commitments.
func (s *SigningSession) GetCommitments() []NonceCommitment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	commitments := make([]NonceCommitment, 0, len(s.Commitments))
	for _, c := range s.Commitments {
		commitments = append(commitments, c)
	}
	return commitments
}

// Complete marks the session as complete with the given signature.
func (s *SigningSession) Complete(signature Signature) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.State = SessionStateComplete
	s.Result = signature
	s.UpdatedAt = time.Now()
}

// Fail marks the session as failed with the given error.
func (s *SigningSession) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.State = SessionStateFailed
	s.Error = err
	s.UpdatedAt = time.Now()
}

// IsExpired returns true if the session has exceeded its timeout.
func (s *SigningSession) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Timeout == 0 {
		return false
	}
	return time.Since(s.CreatedAt) > s.Timeout
}

// SessionManager manages multiple signing sessions.
type SessionManager struct {
	sessions map[string]*SigningSession
	mu       sync.RWMutex
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SigningSession),
	}
}

// CreateSession creates a new signing session.
func (m *SessionManager) CreateSession(id string, scheme SchemeID, message []byte, groupKey PublicKey, threshold int, timeout time.Duration) (*SigningSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[id]; exists {
		return nil, ErrInvalidState
	}

	session := NewSigningSession(id, scheme, message, groupKey, threshold, timeout)
	m.sessions[id] = session
	return session, nil
}

// GetSession returns a session by ID.
func (m *SessionManager) GetSession(id string) (*SigningSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[id]
	if !exists {
		return nil, ErrInvalidState
	}
	return session, nil
}

// DeleteSession removes a session.
func (m *SessionManager) DeleteSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, id)
}

// CleanupExpired removes all expired sessions.
func (m *SessionManager) CleanupExpired(ctx context.Context) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for id, session := range m.sessions {
		if session.IsExpired() {
			delete(m.sessions, id)
			count++
		}
	}
	return count
}

// ListSessions returns all active session IDs.
func (m *SessionManager) ListSessions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}
