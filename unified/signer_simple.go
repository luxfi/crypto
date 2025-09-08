// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Simple unified signer that works with actual crypto APIs

package unified

import (
	"crypto"
	"crypto/rand"
	"fmt"
	
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/mldsa"
)

// SimpleSigner provides unified signing
type SimpleSigner struct {
	blsKey   *bls.SecretKey
	mldsaKey *mldsa.PrivateKey
}

// NewSimpleSigner creates a signer with BLS and ML-DSA
func NewSimpleSigner() (*SimpleSigner, error) {
	// Generate BLS key
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	
	blsKey, err := bls.SecretKeyFromBytes(seed)
	if err != nil {
		return nil, err
	}
	
	// Generate ML-DSA key
	mldsaKey, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		return nil, err
	}
	
	return &SimpleSigner{
		blsKey:   blsKey,
		mldsaKey: mldsaKey,
	}, nil
}

// SignBLS creates a BLS signature
func (s *SimpleSigner) SignBLS(message []byte) ([]byte, error) {
	sig := s.blsKey.Sign(message)
	return bls.SignatureToBytes(sig), nil
}

// VerifyBLS verifies a BLS signature
func (s *SimpleSigner) VerifyBLS(message, signature []byte) bool {
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return false
	}
	pubKey := s.blsKey.PublicKey()
	return bls.Verify(pubKey, sig, message)
}

// SignMLDSA creates an ML-DSA signature
func (s *SimpleSigner) SignMLDSA(message []byte) ([]byte, error) {
	// ML-DSA requires opts, use crypto.Hash(0) for default
	return s.mldsaKey.Sign(rand.Reader, message, crypto.Hash(0))
}

// VerifyMLDSA verifies an ML-DSA signature
func (s *SimpleSigner) VerifyMLDSA(message, signature []byte) bool {
	return s.mldsaKey.PublicKey.Verify(message, signature, crypto.Hash(0))
}

// SignHybrid creates both BLS and ML-DSA signatures
func (s *SimpleSigner) SignHybrid(message []byte) ([]byte, error) {
	blsSig, err := s.SignBLS(message)
	if err != nil {
		return nil, fmt.Errorf("BLS sign failed: %w", err)
	}
	
	mldsaSig, err := s.SignMLDSA(message)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA sign failed: %w", err)
	}
	
	// Combine: [2-byte BLS len][BLS sig][ML-DSA sig]
	result := make([]byte, 2+len(blsSig)+len(mldsaSig))
	result[0] = byte(len(blsSig) >> 8)
	result[1] = byte(len(blsSig))
	copy(result[2:], blsSig)
	copy(result[2+len(blsSig):], mldsaSig)
	
	return result, nil
}

// VerifyHybrid verifies both BLS and ML-DSA signatures
func (s *SimpleSigner) VerifyHybrid(message, signature []byte) bool {
	if len(signature) < 2 {
		return false
	}
	
	blsLen := int(signature[0])<<8 | int(signature[1])
	if len(signature) < 2+blsLen {
		return false
	}
	
	blsSig := signature[2 : 2+blsLen]
	mldsaSig := signature[2+blsLen:]
	
	return s.VerifyBLS(message, blsSig) && s.VerifyMLDSA(message, mldsaSig)
}

// GetBLSPublicKey returns the BLS public key
func (s *SimpleSigner) GetBLSPublicKey() []byte {
	pubKey := s.blsKey.PublicKey()
	return bls.PublicKeyToCompressedBytes(pubKey)
}

// GetMLDSAPublicKey returns the ML-DSA public key
func (s *SimpleSigner) GetMLDSAPublicKey() []byte {
	return s.mldsaKey.PublicKey.Bytes()
}