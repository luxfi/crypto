// Package aead provides authenticated encryption with associated data
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AeadID identifies an AEAD algorithm
type AeadID string

const (
	AES256GCM         AeadID = "aes256gcm"
	ChaCha20Poly1305  AeadID = "chacha20poly1305"
	AES256GCMSIV      AeadID = "aes256gcmsiv"
)

// AEAD interface for authenticated encryption
type AEAD interface {
	// Seal encrypts and authenticates plaintext
	Seal(dst, nonce, plaintext, aad []byte) []byte
	
	// Open decrypts and authenticates ciphertext
	Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
	
	// NonceSize returns the nonce size in bytes
	NonceSize() int
	
	// Overhead returns the authentication tag size
	Overhead() int
	
	// KeySize returns the key size in bytes
	KeySize() int
}

// AES256GCMImpl implements AES-256-GCM
type AES256GCMImpl struct {
	aead cipher.AEAD
}

// NewAES256GCM creates a new AES-256-GCM instance
func NewAES256GCM(key []byte) (AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM requires 32-byte key")
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	return &AES256GCMImpl{aead: aead}, nil
}

// Seal encrypts and authenticates plaintext
func (a *AES256GCMImpl) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic(fmt.Sprintf("invalid nonce size: got %d, want %d", len(nonce), a.NonceSize()))
	}
	
	// GCM handles AAD internally
	return a.aead.Seal(dst, nonce, plaintext, aad)
}

// Open decrypts and authenticates ciphertext
func (a *AES256GCMImpl) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), a.NonceSize())
	}
	
	return a.aead.Open(dst, nonce, ciphertext, aad)
}

// NonceSize returns 96-bit nonce size for GCM
func (a *AES256GCMImpl) NonceSize() int {
	return 12 // 96 bits
}

// Overhead returns 128-bit tag size
func (a *AES256GCMImpl) Overhead() int {
	return 16 // 128 bits
}

// KeySize returns 256-bit key size
func (a *AES256GCMImpl) KeySize() int {
	return 32 // 256 bits
}

// ChaCha20Poly1305Impl implements ChaCha20-Poly1305
type ChaCha20Poly1305Impl struct {
	aead cipher.AEAD
}

// NewChaCha20Poly1305 creates a new ChaCha20-Poly1305 instance
func NewChaCha20Poly1305(key []byte) (AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("ChaCha20-Poly1305 requires 32-byte key")
	}
	
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	
	return &ChaCha20Poly1305Impl{aead: aead}, nil
}

// Seal encrypts and authenticates plaintext
func (c *ChaCha20Poly1305Impl) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != c.NonceSize() {
		panic(fmt.Sprintf("invalid nonce size: got %d, want %d", len(nonce), c.NonceSize()))
	}
	
	return c.aead.Seal(dst, nonce, plaintext, aad)
}

// Open decrypts and authenticates ciphertext
func (c *ChaCha20Poly1305Impl) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != c.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), c.NonceSize())
	}
	
	return c.aead.Open(dst, nonce, ciphertext, aad)
}

// NonceSize returns 96-bit nonce size
func (c *ChaCha20Poly1305Impl) NonceSize() int {
	return 12 // 96 bits (standard IETF variant)
}

// Overhead returns 128-bit tag size
func (c *ChaCha20Poly1305Impl) Overhead() int {
	return 16 // 128 bits
}

// KeySize returns 256-bit key size
func (c *ChaCha20Poly1305Impl) KeySize() int {
	return 32 // 256 bits
}

// GetAEAD returns an AEAD implementation for the given ID
func GetAEAD(id AeadID, key []byte) (AEAD, error) {
	switch id {
	case AES256GCM:
		return NewAES256GCM(key)
	case ChaCha20Poly1305:
		return NewChaCha20Poly1305(key)
	case AES256GCMSIV:
		// AES-GCM-SIV would require additional implementation
		return nil, errors.New("AES-256-GCM-SIV not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported AEAD: %s", id)
	}
}

// NonceGenerator generates deterministic nonces for stream-based protocols
type NonceGenerator struct {
	streamID uint32
	seqNo    uint64
}

// NewNonceGenerator creates a new nonce generator
func NewNonceGenerator(streamID uint32) *NonceGenerator {
	return &NonceGenerator{
		streamID: streamID,
		seqNo:    0,
	}
}

// Next returns the next nonce and increments sequence number
func (ng *NonceGenerator) Next() []byte {
	nonce := make([]byte, 12) // 96-bit nonce
	
	// First 4 bytes: stream ID
	nonce[0] = byte(ng.streamID >> 24)
	nonce[1] = byte(ng.streamID >> 16)
	nonce[2] = byte(ng.streamID >> 8)
	nonce[3] = byte(ng.streamID)
	
	// Next 8 bytes: sequence number
	nonce[4] = byte(ng.seqNo >> 56)
	nonce[5] = byte(ng.seqNo >> 48)
	nonce[6] = byte(ng.seqNo >> 40)
	nonce[7] = byte(ng.seqNo >> 32)
	nonce[8] = byte(ng.seqNo >> 24)
	nonce[9] = byte(ng.seqNo >> 16)
	nonce[10] = byte(ng.seqNo >> 8)
	nonce[11] = byte(ng.seqNo)
	
	ng.seqNo++
	
	return nonce
}

// SetSeqNo sets the sequence number (for resumption)
func (ng *NonceGenerator) SetSeqNo(seqNo uint64) {
	ng.seqNo = seqNo
}

// GetSeqNo returns the current sequence number
func (ng *NonceGenerator) GetSeqNo() uint64 {
	return ng.seqNo
}