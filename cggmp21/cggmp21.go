// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cggmp21 implements the CGGMP21 threshold ECDSA protocol
// Reference: "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
// by Canetti, Gennaro, Goldfeder, Makriyannis, and Peled (2021)
package cggmp21

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

// Signature represents an ECDSA signature
type Signature struct {
	R *big.Int
	S *big.Int
}

// Config contains CGGMP21 protocol configuration
type Config struct {
	Threshold      int // t: Threshold (t+1 parties needed to sign)
	TotalParties   int // n: Total number of parties
	Curve          elliptic.Curve
	SessionTimeout int64 // Timeout for protocol rounds
}

// Party represents a participant in the CGGMP21 protocol
type Party struct {
	ID     ids.NodeID
	Index  int
	Config *Config

	// Key material. The share is unexported: a struct field holding a secret is
	// reached by every reflection encoder there is — json.Marshal, a %+v in a log
	// line, a debug dump — none of which asks for a key. Recovering the share from
	// this type is a method call, so it happens where someone wrote one.
	xi           *big.Int         // secret key share
	PublicKey    *ecdsa.PublicKey // Group public key
	PublicShares map[int]*big.Int // Public key shares from all parties

	// Paillier keys for ZK proofs
	PaillierSK  *PaillierPrivateKey
	PaillierPKs map[int]*PaillierPublicKey

	// Session state
	sessions map[string]*SigningSession

	log log.Logger
	mu  sync.RWMutex
}

// SigningSession represents an active signing session
type SigningSession struct {
	SessionID   string
	Message     []byte
	MessageHash *big.Int

	// Round 1: Commitment. Unexported for the same reason as the share, and with a
	// sharper edge: chi_i = x_i * k_i, so a value carrying both k_i and chi_i gives
	// up the secret share to one modular inverse. This type is returned by the
	// public API, and an exported field is one %+v away from a log line.
	ki             *big.Int // k_i (nonce share)
	gammai         *big.Int // gamma_i (random mask)
	CommitmentSent bool
	Commitments    map[int][]byte // Received commitments

	// Round 2: Reveal
	RevealsSent    bool
	GammaShares    map[int]*big.Int // gamma_j values
	BigGammaShares map[int]*ECPoint // [gamma_j]G points

	// Round 3: Multiplication
	deltaShare     *big.Int         // delta_i = k_i * gamma_i
	chiShare       *big.Int         // chi_i = x_i * k_i
	BigDeltaShares map[int]*ECPoint // [delta_j]G points

	// Round 4: Opening
	Deltas map[int]*big.Int // delta_j values
	BigRx  *ECPoint         // R_x point

	// Final signature
	R *big.Int
	S *big.Int

	// Abort handling
	AbortingParties []int
}

// ECPoint represents an elliptic curve point
type ECPoint struct {
	X, Y *big.Int
}

// NewParty creates a new CGGMP21 party
func NewParty(id ids.NodeID, index int, config *Config, log log.Logger) (*Party, error) {
	if index < 0 || index >= config.TotalParties {
		return nil, errors.New("invalid party index")
	}

	// Generate Paillier keypair for ZK proofs
	paillierSK, paillierPK, err := GeneratePaillierKeyPair(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Paillier keys: %w", err)
	}

	return &Party{
		ID:           id,
		Index:        index,
		Config:       config,
		PublicShares: make(map[int]*big.Int),
		PaillierSK:   paillierSK,
		PaillierPKs:  map[int]*PaillierPublicKey{index: paillierPK},
		sessions:     make(map[string]*SigningSession),
		log:          log,
	}, nil
}

// KeyGen performs distributed key generation
func (p *Party) KeyGen(parties []int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate secret share
	xi, err := rand.Int(rand.Reader, p.Config.Curve.Params().N)
	if err != nil {
		return err
	}
	p.xi = xi

	// Compute public key share [x_i]G
	Xi := ScalarBaseMult(p.Config.Curve, xi)
	p.PublicShares[p.Index] = Xi.X

	// In practice, this would involve communication rounds
	// For now, we simulate having received all shares

	// Compute group public key (would be sum of all shares)
	// Y = sum([x_i]G) for all i

	p.log.Info("Key generation completed",
		log.Stringer("partyID", p.ID),
		log.Int("index", p.Index),
		log.Int("threshold", p.Config.Threshold),
	)

	return nil
}

// InitiateSign starts a new signing session
func (p *Party) InitiateSign(sessionID string, message []byte) (*SigningSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.sessions[sessionID]; exists {
		return nil, errors.New("session already exists")
	}

	// Hash the message
	h := sha256.Sum256(message)
	messageHash := new(big.Int).SetBytes(h[:])

	session := &SigningSession{
		SessionID:      sessionID,
		Message:        message,
		MessageHash:    messageHash,
		Commitments:    make(map[int][]byte),
		GammaShares:    make(map[int]*big.Int),
		BigGammaShares: make(map[int]*ECPoint),
		BigDeltaShares: make(map[int]*ECPoint),
		Deltas:         make(map[int]*big.Int),
	}

	p.sessions[sessionID] = session

	return session, nil
}

// Round1_Commitment generates and broadcasts commitment
func (p *Party) Round1_Commitment(sessionID string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session, exists := p.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	if session.CommitmentSent {
		return nil, errors.New("commitment already sent")
	}

	// Generate k_i and gamma_i
	ki, err := rand.Int(rand.Reader, p.Config.Curve.Params().N)
	if err != nil {
		return nil, err
	}
	gammai, err := rand.Int(rand.Reader, p.Config.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	session.ki = ki
	session.gammai = gammai

	// Compute commitment = H(i, [gamma_i]G)
	bigGammai := ScalarBaseMult(p.Config.Curve, gammai)
	commitment := p.computeCommitment(p.Index, bigGammai)

	session.CommitmentSent = true

	return commitment, nil
}

// Round2_Reveal reveals gamma values after receiving all commitments
func (p *Party) Round2_Reveal(sessionID string, commitments map[int][]byte) (*Round2Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session, exists := p.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	if session.RevealsSent {
		return nil, errors.New("reveals already sent")
	}

	// Store commitments
	for idx, comm := range commitments {
		if idx != p.Index {
			session.Commitments[idx] = comm
		}
	}

	// Create reveal message
	bigGammai := ScalarBaseMult(p.Config.Curve, session.gammai)

	msg := &Round2Message{
		FromIndex: p.Index,
		BigGammaI: bigGammai,
		// In production, include ZK proofs here
	}

	session.RevealsSent = true

	return msg, nil
}

// Round3_Multiply performs multiplication phase
func (p *Party) Round3_Multiply(sessionID string, reveals map[int]*Round2Message) (*Round3Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session, exists := p.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	// Verify commitments match reveals
	for idx, reveal := range reveals {
		if idx == p.Index {
			continue
		}

		expectedComm := p.computeCommitment(idx, reveal.BigGammaI)
		if !bytesEqual(expectedComm, session.Commitments[idx]) {
			return nil, fmt.Errorf("commitment verification failed for party %d", idx)
		}

		session.BigGammaShares[idx] = reveal.BigGammaI
	}

	// Compute delta_i = k_i * gamma_i
	deltai := new(big.Int).Mul(session.ki, session.gammai)
	deltai.Mod(deltai, p.Config.Curve.Params().N)
	session.deltaShare = deltai

	// Compute chi_i = x_i * k_i
	chii := new(big.Int).Mul(p.xi, session.ki)
	chii.Mod(chii, p.Config.Curve.Params().N)
	session.chiShare = chii

	// Compute [delta_i]G
	bigDeltai := ScalarBaseMult(p.Config.Curve, deltai)

	msg := &Round3Message{
		FromIndex: p.Index,
		BigDeltaI: bigDeltai,
		// In production, include encrypted shares and ZK proofs
	}

	return msg, nil
}

// Round4_Open performs the opening phase
func (p *Party) Round4_Open(sessionID string, round3msgs map[int]*Round3Message) (*Round4Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session, exists := p.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	// Store [delta_j]G values
	for idx, msg := range round3msgs {
		if idx != p.Index {
			session.BigDeltaShares[idx] = msg.BigDeltaI
		}
	}

	// In production, perform consistency checks and identify aborts

	msg := &Round4Message{
		FromIndex: p.Index,
		DeltaI:    session.deltaShare,
		// Include proofs of correct multiplication
	}

	return msg, nil
}

// Finalize computes the final signature.
// This requires a full CGGMP21 implementation with Paillier-based MtA
// (multiplicative-to-additive) conversion. Use github.com/luxfi/threshold
// for production threshold signing.
func (p *Party) Finalize(sessionID string, round4msgs map[int]*Round4Message) (*Signature, error) {
	return nil, errors.New("cggmp21: Finalize not implemented — use github.com/luxfi/threshold for production threshold ECDSA")
}

// Helper functions

func (p *Party) computeCommitment(index int, point *ECPoint) []byte {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", index)))
	h.Write(point.X.Bytes())
	h.Write(point.Y.Bytes())
	return h.Sum(nil)
}

func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return &ECPoint{X: x, Y: y}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Message types for protocol rounds

type Round2Message struct {
	FromIndex int
	BigGammaI *ECPoint
	// ZK proofs would be included here
}

type Round3Message struct {
	FromIndex int
	BigDeltaI *ECPoint
	// Encrypted shares and proofs
}

type Round4Message struct {
	FromIndex int
	DeltaI    *big.Int
	// Opening proofs
}

// IdentifiableAbort contains information about a misbehaving party
type IdentifiableAbort struct {
	AbortingParty int
	Round         int
	Proof         []byte
}

// VerifySignature verifies a threshold signature
func VerifySignature(pubKey *ecdsa.PublicKey, message []byte, sig *Signature) bool {
	h := sha256.Sum256(message)
	return ecdsa.Verify(pubKey, h[:], sig.R, sig.S)
}
