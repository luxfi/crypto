// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Package mldsa provides REAL ML-DSA (FIPS 204) implementation using circl

package mldsa

import (
	"crypto"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Mode represents the ML-DSA parameter set
type Mode int

const (
	MLDSA44 Mode = 2 // Level 2
	MLDSA65 Mode = 3 // Level 3
	MLDSA87 Mode = 5 // Level 5
)

// Security parameters for ML-DSA (Module Lattice Digital Signature Algorithm)
const (
	// ML-DSA-44 (Level 2 security)
	MLDSA44PublicKeySize  = mldsa44.PublicKeySize
	MLDSA44PrivateKeySize = mldsa44.PrivateKeySize
	MLDSA44SignatureSize  = mldsa44.SignatureSize

	// ML-DSA-65 (Level 3 security)
	MLDSA65PublicKeySize  = mldsa65.PublicKeySize
	MLDSA65PrivateKeySize = mldsa65.PrivateKeySize
	MLDSA65SignatureSize  = mldsa65.SignatureSize

	// ML-DSA-87 (Level 5 security)
	MLDSA87PublicKeySize  = mldsa87.PublicKeySize
	MLDSA87PrivateKeySize = mldsa87.PrivateKeySize
	MLDSA87SignatureSize  = mldsa87.SignatureSize
)

// PublicKey represents an ML-DSA public key
type PublicKey struct {
	mode Mode
	key  interface{} // Can be mldsa44.PublicKey, mldsa65.PublicKey, or mldsa87.PublicKey
}

// PrivateKey represents an ML-DSA private key
type PrivateKey struct {
	PublicKey *PublicKey
	mode      Mode
	key       interface{} // Can be mldsa44.PrivateKey, mldsa65.PrivateKey, or mldsa87.PrivateKey
}

// GenerateKey generates a new ML-DSA key pair using REAL implementation
func GenerateKey(rand io.Reader, mode Mode) (*PrivateKey, error) {
	if rand == nil {
		return nil, errors.New("random source is nil")
	}

	switch mode {
	case MLDSA44:
		pub, priv, err := mldsa44.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pub,
			},
			mode: mode,
			key:  priv,
		}, nil

	case MLDSA65:
		pub, priv, err := mldsa65.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pub,
			},
			mode: mode,
			key:  priv,
		}, nil

	case MLDSA87:
		pub, priv, err := mldsa87.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pub,
			},
			mode: mode,
			key:  priv,
		}, nil

	default:
		return nil, errors.New("invalid ML-DSA mode")
	}
}

// Sign creates a REAL signature for the given message
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}

	switch priv.mode {
	case MLDSA44:
		if key, ok := priv.key.(*mldsa44.PrivateKey); ok {
			return key.Sign(rand, message, opts)
		}
	case MLDSA65:
		if key, ok := priv.key.(*mldsa65.PrivateKey); ok {
			return key.Sign(rand, message, opts)
		}
	case MLDSA87:
		if key, ok := priv.key.(*mldsa87.PrivateKey); ok {
			return key.Sign(rand, message, opts)
		}
	}

	return nil, errors.New("invalid key type")
}

// Verify verifies a REAL signature using the public key
func (pub *PublicKey) Verify(message, signature []byte, opts crypto.SignerOpts) bool {
	if pub == nil {
		return false
	}

	// Use empty context (nil) for ML-DSA verification
	switch pub.mode {
	case MLDSA44:
		if key, ok := pub.key.(*mldsa44.PublicKey); ok {
			return mldsa44.Verify(key, message, nil, signature)  // nil context
		}
	case MLDSA65:
		if key, ok := pub.key.(*mldsa65.PublicKey); ok {
			return mldsa65.Verify(key, message, nil, signature)  // nil context
		}
	case MLDSA87:
		if key, ok := pub.key.(*mldsa87.PublicKey); ok {
			return mldsa87.Verify(key, message, nil, signature)  // nil context
		}
	}

	return false
}

// Bytes returns the public key as bytes
func (pub *PublicKey) Bytes() []byte {
	switch pub.mode {
	case MLDSA44:
		if key, ok := pub.key.(*mldsa44.PublicKey); ok {
			data, _ := key.MarshalBinary()
			return data
		}
	case MLDSA65:
		if key, ok := pub.key.(*mldsa65.PublicKey); ok {
			data, _ := key.MarshalBinary()
			return data
		}
	case MLDSA87:
		if key, ok := pub.key.(*mldsa87.PublicKey); ok {
			data, _ := key.MarshalBinary()
			return data
		}
	}
	return nil
}

// Bytes returns the private key as bytes
func (priv *PrivateKey) Bytes() []byte {
	switch priv.mode {
	case MLDSA44:
		if key, ok := priv.key.(*mldsa44.PrivateKey); ok {
			data, _ := key.MarshalBinary()
			return data
		}
	case MLDSA65:
		if key, ok := priv.key.(*mldsa65.PrivateKey); ok {
			data, _ := key.MarshalBinary()
			return data
		}
	case MLDSA87:
		if key, ok := priv.key.(*mldsa87.PrivateKey); ok {
			data, _ := key.MarshalBinary()
			return data
		}
	}
	return nil
}

// PublicKeyFromBytes reconstructs a public key from bytes
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	switch mode {
	case MLDSA44:
		if len(data) != MLDSA44PublicKeySize {
			return nil, errors.New("invalid public key size for ML-DSA-44")
		}
		var key mldsa44.PublicKey
		if err := key.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return &PublicKey{
			mode: mode,
			key:  &key,
		}, nil

	case MLDSA65:
		if len(data) != MLDSA65PublicKeySize {
			return nil, errors.New("invalid public key size for ML-DSA-65")
		}
		var key mldsa65.PublicKey
		if err := key.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return &PublicKey{
			mode: mode,
			key:  &key,
		}, nil

	case MLDSA87:
		if len(data) != MLDSA87PublicKeySize {
			return nil, errors.New("invalid public key size for ML-DSA-87")
		}
		var key mldsa87.PublicKey
		if err := key.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return &PublicKey{
			mode: mode,
			key:  &key,
		}, nil

	default:
		return nil, errors.New("invalid ML-DSA mode")
	}
}

// PrivateKeyFromBytes reconstructs a private key from bytes
func PrivateKeyFromBytes(data []byte, mode Mode) (*PrivateKey, error) {
	switch mode {
	case MLDSA44:
		if len(data) != MLDSA44PrivateKeySize {
			return nil, errors.New("invalid private key size for ML-DSA-44")
		}
		var privKey mldsa44.PrivateKey
		if err := privKey.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		
		// Extract public key from private key
		pubKey := privKey.Public().(*mldsa44.PublicKey)
		
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pubKey,
			},
			mode: mode,
			key:  &privKey,
		}, nil

	case MLDSA65:
		if len(data) != MLDSA65PrivateKeySize {
			return nil, errors.New("invalid private key size for ML-DSA-65")
		}
		var privKey mldsa65.PrivateKey
		if err := privKey.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		
		pubKey := privKey.Public().(*mldsa65.PublicKey)
		
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pubKey,
			},
			mode: mode,
			key:  &privKey,
		}, nil

	case MLDSA87:
		if len(data) != MLDSA87PrivateKeySize {
			return nil, errors.New("invalid private key size for ML-DSA-87")
		}
		var privKey mldsa87.PrivateKey
		if err := privKey.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		
		pubKey := privKey.Public().(*mldsa87.PublicKey)
		
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pubKey,
			},
			mode: mode,
			key:  &privKey,
		}, nil

	default:
		return nil, errors.New("invalid ML-DSA mode")
	}
}

// String returns the string representation of the mode
func (m Mode) String() string {
	switch m {
	case MLDSA44:
		return "ML-DSA-44"
	case MLDSA65:
		return "ML-DSA-65"
	case MLDSA87:
		return "ML-DSA-87"
	default:
		return "Unknown"
	}
}