// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package slhdsa implements SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
// using Cloudflare's circl library with automatic CGO optimizations when available.
//
// SLH-DSA (FIPS 205, formerly SPHINCS+) is a post-quantum signature scheme based on
// hash functions. It provides quantum-resistant digital signatures with stateless operation.
package slhdsa

import (
	"crypto"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Mode represents different security levels and variants of SLH-DSA
type Mode int

const (
	// SHA2_128s provides 128-bit security with small signatures (NIST Level 1)
	SHA2_128s Mode = iota
	// SHAKE_128s provides 128-bit security with small signatures using SHAKE (NIST Level 1)
	SHAKE_128s
	// SHA2_128f provides 128-bit security with fast signing (NIST Level 1)
	SHA2_128f
	// SHAKE_128f provides 128-bit security with fast signing using SHAKE (NIST Level 1)
	SHAKE_128f

	// SHA2_192s provides 192-bit security with small signatures (NIST Level 3)
	SHA2_192s
	// SHAKE_192s provides 192-bit security with small signatures using SHAKE (NIST Level 3)
	SHAKE_192s
	// SHA2_192f provides 192-bit security with fast signing (NIST Level 3)
	SHA2_192f
	// SHAKE_192f provides 192-bit security with fast signing using SHAKE (NIST Level 3)
	SHAKE_192f

	// SHA2_256s provides 256-bit security with small signatures (NIST Level 5)
	SHA2_256s
	// SHAKE_256s provides 256-bit security with small signatures using SHAKE (NIST Level 5)
	SHAKE_256s
	// SHA2_256f provides 256-bit security with fast signing (NIST Level 5)
	SHA2_256f
	// SHAKE_256f provides 256-bit security with fast signing using SHAKE (NIST Level 5)
	SHAKE_256f
)

var (
	ErrInvalidMode      = errors.New("invalid SLH-DSA mode")
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidSignature = errors.New("invalid signature")
)

// PrivateKey represents an SLH-DSA private key
type PrivateKey struct {
	mode      Mode
	secretKey []byte
	PublicKey *PublicKey
}

// PublicKey represents an SLH-DSA public key
type PublicKey struct {
	mode      Mode
	publicKey []byte
}

// modeToID converts our Mode to circl's ID
func modeToID(mode Mode) slhdsa.ID {
	switch mode {
	case SHA2_128s:
		return slhdsa.SHA2_128s
	case SHAKE_128s:
		return slhdsa.SHAKE_128s
	case SHA2_128f:
		return slhdsa.SHA2_128f
	case SHAKE_128f:
		return slhdsa.SHAKE_128f
	case SHA2_192s:
		return slhdsa.SHA2_192s
	case SHAKE_192s:
		return slhdsa.SHAKE_192s
	case SHA2_192f:
		return slhdsa.SHA2_192f
	case SHAKE_192f:
		return slhdsa.SHAKE_192f
	case SHA2_256s:
		return slhdsa.SHA2_256s
	case SHAKE_256s:
		return slhdsa.SHAKE_256s
	case SHA2_256f:
		return slhdsa.SHA2_256f
	case SHAKE_256f:
		return slhdsa.SHAKE_256f
	default:
		return 0 // invalid
	}
}

// GetPublicKeySize returns the size of a public key for the given mode
func GetPublicKeySize(mode Mode) int {
	id := modeToID(mode)
	if !id.IsValid() {
		return 0
	}
	params := id.String()
	// Public key is 2*n where n depends on security level:
	// 128-bit: n=16 -> 32 bytes
	// 192-bit: n=24 -> 48 bytes
	// 256-bit: n=32 -> 64 bytes
	switch mode {
	case SHA2_128s, SHAKE_128s, SHA2_128f, SHAKE_128f:
		return 32
	case SHA2_192s, SHAKE_192s, SHA2_192f, SHAKE_192f:
		return 48
	case SHA2_256s, SHAKE_256s, SHA2_256f, SHAKE_256f:
		return 64
	default:
		_ = params // avoid unused variable
		return 0
	}
}

// GetSignatureSize returns the size of a signature for the given mode
func GetSignatureSize(mode Mode) int {
	id := modeToID(mode)
	if !id.IsValid() {
		return 0
	}
	// Signature sizes vary by mode (small vs fast)
	// These are from FIPS 205 specification
	switch mode {
	case SHA2_128s, SHAKE_128s:
		return 7856 // 128-bit small
	case SHA2_128f, SHAKE_128f:
		return 17088 // 128-bit fast
	case SHA2_192s, SHAKE_192s:
		return 16224 // 192-bit small
	case SHA2_192f, SHAKE_192f:
		return 35664 // 192-bit fast
	case SHA2_256s, SHAKE_256s:
		return 29792 // 256-bit small
	case SHA2_256f, SHAKE_256f:
		return 49856 // 256-bit fast
	default:
		return 0
	}
}

// GenerateKey generates a new SLH-DSA key pair using circl
func GenerateKey(rand io.Reader, mode Mode) (*PrivateKey, error) {
	id := modeToID(mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	pub, priv, err := slhdsa.GenerateKey(rand, id)
	if err != nil {
		return nil, err
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		mode:      mode,
		secretKey: privBytes,
		PublicKey: &PublicKey{
			mode:      mode,
			publicKey: pubBytes,
		},
	}, nil
}

// Sign signs a message with the private key using circl
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	id := modeToID(priv.mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	var sk slhdsa.PrivateKey
	sk.ID = id
	if err := (&sk).UnmarshalBinary(priv.secretKey); err != nil {
		return nil, err
	}

	// Use deterministic signing (context = nil)
	msg := slhdsa.NewMessage(message)
	signature, err := slhdsa.SignDeterministic(&sk, msg, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify verifies a signature with the public key using circl
func (pub *PublicKey) Verify(message, signature []byte, opts crypto.SignerOpts) bool {
	id := modeToID(pub.mode)
	if !id.IsValid() {
		return false
	}

	var pk slhdsa.PublicKey
	pk.ID = id
	if err := (&pk).UnmarshalBinary(pub.publicKey); err != nil {
		return false
	}

	msg := slhdsa.NewMessage(message)
	return slhdsa.Verify(&pk, msg, signature, nil)
}

// Public returns the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.PublicKey
}

// Bytes returns the serialized private key
func (priv *PrivateKey) Bytes() []byte {
	return priv.secretKey
}

// Bytes returns the serialized public key
func (pub *PublicKey) Bytes() []byte {
	return pub.publicKey
}

// PrivateKeyFromBytes deserializes a private key
func PrivateKeyFromBytes(mode Mode, data []byte) (*PrivateKey, error) {
	id := modeToID(mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	// Validate size
	var sk slhdsa.PrivateKey
	sk.ID = id
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, ErrInvalidKeySize
	}

	// Extract public key
	pub := sk.PublicKey()
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		mode:      mode,
		secretKey: data,
		PublicKey: &PublicKey{
			mode:      mode,
			publicKey: pubBytes,
		},
	}, nil
}

// PublicKeyFromBytes deserializes a public key
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	expectedSize := GetPublicKeySize(mode)
	if expectedSize == 0 {
		return nil, ErrInvalidMode
	}
	if len(data) != expectedSize {
		return nil, ErrInvalidKeySize
	}

	id := modeToID(mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	// Validate by trying to unmarshal
	var pk slhdsa.PublicKey
	pk.ID = id
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &PublicKey{
		mode:      mode,
		publicKey: data,
	}, nil
}
