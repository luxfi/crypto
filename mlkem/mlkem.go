// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Package mlkem provides REAL ML-KEM (FIPS 203) implementation using circl

package mlkem

import (
	crypto_rand "crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// Mode represents the ML-KEM parameter set
type Mode int

const (
	MLKEM512  Mode = iota // Level 1 security
	MLKEM768              // Level 3 security
	MLKEM1024             // Level 5 security
)

// Security parameters for ML-KEM (Module Lattice Key Encapsulation Mechanism)
const (
	// ML-KEM-512 (Level 1 security)
	MLKEM512PublicKeySize   = mlkem512.PublicKeySize
	MLKEM512PrivateKeySize  = mlkem512.PrivateKeySize
	MLKEM512CiphertextSize  = mlkem512.CiphertextSize
	MLKEM512SharedSecretSize = mlkem512.SharedKeySize

	// ML-KEM-768 (Level 3 security)
	MLKEM768PublicKeySize   = mlkem768.PublicKeySize
	MLKEM768PrivateKeySize  = mlkem768.PrivateKeySize
	MLKEM768CiphertextSize  = mlkem768.CiphertextSize
	MLKEM768SharedSecretSize = mlkem768.SharedKeySize

	// ML-KEM-1024 (Level 5 security)
	MLKEM1024PublicKeySize   = mlkem1024.PublicKeySize
	MLKEM1024PrivateKeySize  = mlkem1024.PrivateKeySize
	MLKEM1024CiphertextSize  = mlkem1024.CiphertextSize
	MLKEM1024SharedSecretSize = mlkem1024.SharedKeySize
)

// PublicKey represents an ML-KEM public key
type PublicKey struct {
	mode Mode
	key  interface{} // Can be mlkem512.PublicKey, mlkem768.PublicKey, or mlkem1024.PublicKey
}

// PrivateKey represents an ML-KEM private key
type PrivateKey struct {
	PublicKey *PublicKey
	mode      Mode
	key       interface{} // Can be mlkem512.PrivateKey, mlkem768.PrivateKey, or mlkem1024.PrivateKey
}

// EncapsulationResult holds the result of encapsulation
type EncapsulationResult struct {
	Ciphertext   []byte
	SharedSecret []byte
}

// GenerateKeyPair generates a new ML-KEM key pair using REAL implementation
func GenerateKeyPair(rand io.Reader, mode Mode) (*PrivateKey, *PublicKey, error) {
	if rand == nil {
		rand = crypto_rand.Reader
	}

	switch mode {
	case MLKEM512:
		pub, priv, err := mlkem512.GenerateKeyPair(rand)
		if err != nil {
			return nil, nil, err
		}
		
		return &PrivateKey{
				PublicKey: &PublicKey{
					mode: mode,
					key:  pub,
				},
				mode: mode,
				key:  priv,
			}, &PublicKey{
				mode: mode,
				key:  pub,
			}, nil

	case MLKEM768:
		pub, priv, err := mlkem768.GenerateKeyPair(rand)
		if err != nil {
			return nil, nil, err
		}
		
		return &PrivateKey{
				PublicKey: &PublicKey{
					mode: mode,
					key:  pub,
				},
				mode: mode,
				key:  priv,
			}, &PublicKey{
				mode: mode,
				key:  pub,
			}, nil

	case MLKEM1024:
		pub, priv, err := mlkem1024.GenerateKeyPair(rand)
		if err != nil {
			return nil, nil, err
		}
		
		return &PrivateKey{
				PublicKey: &PublicKey{
					mode: mode,
					key:  pub,
				},
				mode: mode,
				key:  priv,
			}, &PublicKey{
				mode: mode,
				key:  pub,
			}, nil

	default:
		return nil, nil, errors.New("invalid ML-KEM mode")
	}
}

// Encapsulate generates a ciphertext and shared secret using REAL implementation
func (pub *PublicKey) Encapsulate(rand io.Reader) (*EncapsulationResult, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}

	if rand == nil {
		rand = crypto_rand.Reader
	}

	switch pub.mode {
	case MLKEM512:
		if key, ok := pub.key.(*mlkem512.PublicKey); ok {
			seed := make([]byte, mlkem512.EncapsulationSeedSize)
			if _, err := io.ReadFull(rand, seed); err != nil {
				return nil, err
			}
			ct := make([]byte, mlkem512.CiphertextSize)
			ss := make([]byte, mlkem512.SharedKeySize)
			key.EncapsulateTo(ct, ss, seed)
			return &EncapsulationResult{
				Ciphertext:   ct,
				SharedSecret: ss,
			}, nil
		}

	case MLKEM768:
		if key, ok := pub.key.(*mlkem768.PublicKey); ok {
			seed := make([]byte, mlkem768.EncapsulationSeedSize)
			if _, err := io.ReadFull(rand, seed); err != nil {
				return nil, err
			}
			ct := make([]byte, mlkem768.CiphertextSize)
			ss := make([]byte, mlkem768.SharedKeySize)
			key.EncapsulateTo(ct, ss, seed)
			return &EncapsulationResult{
				Ciphertext:   ct,
				SharedSecret: ss,
			}, nil
		}

	case MLKEM1024:
		if key, ok := pub.key.(*mlkem1024.PublicKey); ok {
			seed := make([]byte, mlkem1024.EncapsulationSeedSize)
			if _, err := io.ReadFull(rand, seed); err != nil {
				return nil, err
			}
			ct := make([]byte, mlkem1024.CiphertextSize)
			ss := make([]byte, mlkem1024.SharedKeySize)
			key.EncapsulateTo(ct, ss, seed)
			return &EncapsulationResult{
				Ciphertext:   ct,
				SharedSecret: ss,
			}, nil
		}
	}

	return nil, errors.New("invalid key type")
}

// Decapsulate recovers the shared secret from ciphertext using REAL implementation
func (priv *PrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}

	switch priv.mode {
	case MLKEM512:
		if key, ok := priv.key.(*mlkem512.PrivateKey); ok {
			if len(ciphertext) != mlkem512.CiphertextSize {
				return nil, errors.New("invalid ciphertext size for ML-KEM-512")
			}
			ss := make([]byte, mlkem512.SharedKeySize)
			key.DecapsulateTo(ss, ciphertext)
			return ss, nil
		}

	case MLKEM768:
		if key, ok := priv.key.(*mlkem768.PrivateKey); ok {
			if len(ciphertext) != mlkem768.CiphertextSize {
				return nil, errors.New("invalid ciphertext size for ML-KEM-768")
			}
			ss := make([]byte, mlkem768.SharedKeySize)
			key.DecapsulateTo(ss, ciphertext)
			return ss, nil
		}

	case MLKEM1024:
		if key, ok := priv.key.(*mlkem1024.PrivateKey); ok {
			if len(ciphertext) != mlkem1024.CiphertextSize {
				return nil, errors.New("invalid ciphertext size for ML-KEM-1024")
			}
			ss := make([]byte, mlkem1024.SharedKeySize)
			key.DecapsulateTo(ss, ciphertext)
			return ss, nil
		}
	}

	return nil, errors.New("invalid key type")
}

// Bytes returns the public key as bytes
func (pub *PublicKey) Bytes() []byte {
	switch pub.mode {
	case MLKEM512:
		if key, ok := pub.key.(*mlkem512.PublicKey); ok {
			data := make([]byte, MLKEM512PublicKeySize)
			key.Pack(data)
			return data
		}
	case MLKEM768:
		if key, ok := pub.key.(*mlkem768.PublicKey); ok {
			data := make([]byte, MLKEM768PublicKeySize)
			key.Pack(data)
			return data
		}
	case MLKEM1024:
		if key, ok := pub.key.(*mlkem1024.PublicKey); ok {
			data := make([]byte, MLKEM1024PublicKeySize)
			key.Pack(data)
			return data
		}
	}
	return nil
}

// Bytes returns the private key as bytes
func (priv *PrivateKey) Bytes() []byte {
	switch priv.mode {
	case MLKEM512:
		if key, ok := priv.key.(*mlkem512.PrivateKey); ok {
			data := make([]byte, MLKEM512PrivateKeySize)
			key.Pack(data)
			return data
		}
	case MLKEM768:
		if key, ok := priv.key.(*mlkem768.PrivateKey); ok {
			data := make([]byte, MLKEM768PrivateKeySize)
			key.Pack(data)
			return data
		}
	case MLKEM1024:
		if key, ok := priv.key.(*mlkem1024.PrivateKey); ok {
			data := make([]byte, MLKEM1024PrivateKeySize)
			key.Pack(data)
			return data
		}
	}
	return nil
}

// PublicKeyFromBytes reconstructs a public key from bytes
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	switch mode {
	case MLKEM512:
		if len(data) != MLKEM512PublicKeySize {
			return nil, errors.New("invalid public key size for ML-KEM-512")
		}
		var key mlkem512.PublicKey
		if err := key.Unpack(data); err != nil {
			return nil, err
		}
		return &PublicKey{
			mode: mode,
			key:  &key,
		}, nil

	case MLKEM768:
		if len(data) != MLKEM768PublicKeySize {
			return nil, errors.New("invalid public key size for ML-KEM-768")
		}
		var key mlkem768.PublicKey
		if err := key.Unpack(data); err != nil {
			return nil, err
		}
		return &PublicKey{
			mode: mode,
			key:  &key,
		}, nil

	case MLKEM1024:
		if len(data) != MLKEM1024PublicKeySize {
			return nil, errors.New("invalid public key size for ML-KEM-1024")
		}
		var key mlkem1024.PublicKey
		if err := key.Unpack(data); err != nil {
			return nil, err
		}
		return &PublicKey{
			mode: mode,
			key:  &key,
		}, nil

	default:
		return nil, errors.New("invalid ML-KEM mode")
	}
}

// PrivateKeyFromBytes reconstructs a private key from bytes
func PrivateKeyFromBytes(data []byte, mode Mode) (*PrivateKey, error) {
	switch mode {
	case MLKEM512:
		if len(data) != MLKEM512PrivateKeySize {
			return nil, errors.New("invalid private key size for ML-KEM-512")
		}
		var privKey mlkem512.PrivateKey
		if err := privKey.Unpack(data); err != nil {
			return nil, err
		}
		
		// Extract public key from private key
		pubKey := privKey.Public().(*mlkem512.PublicKey)
		
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pubKey,
			},
			mode: mode,
			key:  &privKey,
		}, nil

	case MLKEM768:
		if len(data) != MLKEM768PrivateKeySize {
			return nil, errors.New("invalid private key size for ML-KEM-768")
		}
		var privKey mlkem768.PrivateKey
		if err := privKey.Unpack(data); err != nil {
			return nil, err
		}
		
		pubKey := privKey.Public().(*mlkem768.PublicKey)
		
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pubKey,
			},
			mode: mode,
			key:  &privKey,
		}, nil

	case MLKEM1024:
		if len(data) != MLKEM1024PrivateKeySize {
			return nil, errors.New("invalid private key size for ML-KEM-1024")
		}
		var privKey mlkem1024.PrivateKey
		if err := privKey.Unpack(data); err != nil {
			return nil, err
		}
		
		pubKey := privKey.Public().(*mlkem1024.PublicKey)
		
		return &PrivateKey{
			PublicKey: &PublicKey{
				mode: mode,
				key:  pubKey,
			},
			mode: mode,
			key:  &privKey,
		}, nil

	default:
		return nil, errors.New("invalid ML-KEM mode")
	}
}

// String returns the string representation of the mode
func (m Mode) String() string {
	switch m {
	case MLKEM512:
		return "ML-KEM-512"
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return "Unknown"
	}
}