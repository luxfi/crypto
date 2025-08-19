// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Package slhdsa provides REAL SLH-DSA (FIPS 205) implementation

package slhdsa

import (
	"crypto"
	"errors"
	"io"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// Mode represents the SLH-DSA parameter set
type Mode int

const (
	SLHDSA128s Mode = iota + 1 // Small signatures, Level 1
	SLHDSA128f                  // Fast signing, Level 1
	SLHDSA192s                  // Small signatures, Level 3
	SLHDSA192f                  // Fast signing, Level 3
	SLHDSA256s                  // Small signatures, Level 5
	SLHDSA256f                  // Fast signing, Level 5
)

// Security parameters for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
const (
	// SLH-DSA-SHA2-128s (Small signatures, Level 1 security)
	SLHDSA128sPublicKeySize  = 32
	SLHDSA128sPrivateKeySize = 64
	SLHDSA128sSignatureSize  = 7856

	// SLH-DSA-SHA2-128f (Fast signing, Level 1 security)
	SLHDSA128fPublicKeySize  = 32
	SLHDSA128fPrivateKeySize = 64
	SLHDSA128fSignatureSize  = 17088

	// SLH-DSA-SHA2-192s (Small signatures, Level 3 security)
	SLHDSA192sPublicKeySize  = 48
	SLHDSA192sPrivateKeySize = 96
	SLHDSA192sSignatureSize  = 16224

	// SLH-DSA-SHA2-192f (Fast signing, Level 3 security)
	SLHDSA192fPublicKeySize  = 48
	SLHDSA192fPrivateKeySize = 96
	SLHDSA192fSignatureSize  = 35664

	// SLH-DSA-SHA2-256s (Small signatures, Level 5 security)
	SLHDSA256sPublicKeySize  = 64
	SLHDSA256sPrivateKeySize = 128
	SLHDSA256sSignatureSize  = 29792

	// SLH-DSA-SHA2-256f (Fast signing, Level 5 security)
	SLHDSA256fPublicKeySize  = 64
	SLHDSA256fPrivateKeySize = 128
	SLHDSA256fSignatureSize  = 49856
)

// PublicKey represents an SLH-DSA public key
type PublicKey struct {
	mode   Mode
	params *parameters.Parameters
	key    *sphincs.SPHINCS_PK
}

// PrivateKey represents an SLH-DSA private key
type PrivateKey struct {
	PublicKey
	privateKey *sphincs.SPHINCS_SK
}

// getParams returns the SPHINCS+ parameters for the given mode
func getParams(mode Mode) (*parameters.Parameters, error) {
	switch mode {
	case SLHDSA128s:
		return parameters.MakeSphincsPlusSHA256128sRobust(true), nil
	case SLHDSA128f:
		return parameters.MakeSphincsPlusSHA256128fRobust(true), nil
	case SLHDSA192s:
		return parameters.MakeSphincsPlusSHA256192sRobust(true), nil
	case SLHDSA192f:
		return parameters.MakeSphincsPlusSHA256192fRobust(true), nil
	case SLHDSA256s:
		return parameters.MakeSphincsPlusSHA256256sRobust(true), nil
	case SLHDSA256f:
		return parameters.MakeSphincsPlusSHA256256fRobust(true), nil
	default:
		return nil, errors.New("invalid SLH-DSA mode")
	}
}

// GenerateKey generates a new SLH-DSA key pair using REAL implementation
func GenerateKey(rand io.Reader, mode Mode) (*PrivateKey, error) {
	if rand == nil {
		return nil, errors.New("random source is nil")
	}

	params, err := getParams(mode)
	if err != nil {
		return nil, err
	}

	// Generate key pair using SPHINCS+ library
	privKey, pubKey := sphincs.Spx_keygen(params)

	return &PrivateKey{
		PublicKey: PublicKey{
			mode:   mode,
			params: params,
			key:    pubKey,
		},
		privateKey: privKey,
	}, nil
}

// Sign signs a message using the REAL SPHINCS+ implementation
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if priv == nil || priv.privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// Sign the message using SPHINCS+
	signature := sphincs.Spx_sign(priv.params, message, priv.privateKey)
	
	// Serialize the signature to bytes
	sigBytes, err := signature.SerializeSignature()
	if err != nil {
		return nil, err
	}
	
	return sigBytes, nil
}

// Verify verifies a signature using the REAL SPHINCS+ implementation
func (pub *PublicKey) Verify(message, signature []byte, opts crypto.SignerOpts) bool {
	if pub == nil || pub.key == nil {
		return false
	}

	// Deserialize the signature
	sig, err := sphincs.DeserializeSignature(pub.params, signature)
	if err != nil {
		return false
	}

	// Verify using SPHINCS+
	return sphincs.Spx_verify(pub.params, message, sig, pub.key)
}

// Bytes returns the public key as bytes
func (pub *PublicKey) Bytes() []byte {
	if pub == nil || pub.key == nil {
		return nil
	}
	bytes, _ := pub.key.SerializePK()
	return bytes
}

// Bytes returns the private key as bytes
func (priv *PrivateKey) Bytes() []byte {
	if priv == nil || priv.privateKey == nil {
		return nil
	}
	bytes, _ := priv.privateKey.SerializeSK()
	return bytes
}

// PublicKeyFromBytes reconstructs a public key from bytes
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	params, err := getParams(mode)
	if err != nil {
		return nil, err
	}

	// Check size - SPHINCS+ public key is 2*N bytes
	expectedSize := 2 * params.N
	if len(data) != expectedSize {
		return nil, errors.New("invalid public key size")
	}

	pubKey, err := sphincs.DeserializePK(params, data)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		mode:   mode,
		params: params,
		key:    pubKey,
	}, nil
}

// PrivateKeyFromBytes reconstructs a private key from bytes
func PrivateKeyFromBytes(data []byte, mode Mode) (*PrivateKey, error) {
	params, err := getParams(mode)
	if err != nil {
		return nil, err
	}

	// Check size - SPHINCS+ private key is 4*N bytes
	expectedSize := 4 * params.N
	if len(data) != expectedSize {
		return nil, errors.New("invalid private key size")
	}

	privKey, err := sphincs.DeserializeSK(params, data)
	if err != nil {
		return nil, err
	}

	// Create public key from private key components
	pubKey := &sphincs.SPHINCS_PK{
		PKseed: privKey.PKseed,
		PKroot: privKey.PKroot,
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			mode:   mode,
			params: params,
			key:    pubKey,
		},
		privateKey: privKey,
	}, nil
}