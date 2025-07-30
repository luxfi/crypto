// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// Constants for domain separation tags
const (
	DSTSignature         = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	DSTProofOfPossession = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
)

// DirectPublicKey represents a BLS public key using G1
type DirectPublicKey struct {
	point bls12381.G1
}

// DirectSignature represents a BLS signature using G2
type DirectSignature struct {
	point bls12381.G2
}

// DirectSecretKey represents a BLS secret key
type DirectSecretKey struct {
	scalar bls12381.Scalar
}

// GenerateKey generates a new BLS secret key
func GenerateKey(reader io.Reader) (*DirectSecretKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	
	// Generate 32 random bytes
	ikm := make([]byte, 32)
	if _, err := io.ReadFull(reader, ikm); err != nil {
		return nil, err
	}
	
	// Convert to scalar
	var scalar bls12381.Scalar
	scalar.Random(reader)
	
	return &DirectSecretKey{scalar: scalar}, nil
}

// PublicKey returns the public key corresponding to the secret key
func (sk *DirectSecretKey) PublicKey() *DirectPublicKey {
	pk := new(DirectPublicKey)
	pk.point.ScalarMult(&sk.scalar, bls12381.G1Generator())
	return pk
}

// Sign creates a signature for the given message
func (sk *DirectSecretKey) Sign(msg []byte) *DirectSignature {
	// Hash message to G2
	var msgPoint bls12381.G2
	msgPoint.Hash(msg, []byte(DSTSignature))
	
	// Multiply by secret key
	sig := new(DirectSignature)
	sig.point.ScalarMult(&sk.scalar, &msgPoint)
	
	return sig
}

// SignProofOfPossession creates a proof of possession signature
func (sk *DirectSecretKey) SignProofOfPossession(msg []byte) *DirectSignature {
	// Hash message to G2 with PoP DST
	var msgPoint bls12381.G2
	msgPoint.Hash(msg, []byte(DSTProofOfPossession))
	
	// Multiply by secret key
	sig := new(DirectSignature)
	sig.point.ScalarMult(&sk.scalar, &msgPoint)
	
	return sig
}

// Verify verifies a signature against a public key and message
func Verify2(pk *DirectPublicKey, sig *DirectSignature, msg []byte) bool {
	// Hash message to G2
	var msgPoint bls12381.G2
	msgPoint.Hash(msg, []byte(DSTSignature))
	
	// e(pk, H(m)) == e(G1, sig)
	g1Gen := bls12381.G1Generator()
	
	// Prepare for pairing check: e(pk, H(m)) * e(-G1, sig) == 1
	return bls12381.ProdPairFrac(
		[]*bls12381.G1{&pk.point, g1Gen},
		[]*bls12381.G2{&msgPoint, &sig.point},
		[]int{1, -1},
	).IsIdentity()
}

// VerifyProofOfPossession2 verifies a proof of possession signature
func VerifyProofOfPossession2(pk *DirectPublicKey, sig *DirectSignature, msg []byte) bool {
	// Hash message to G2 with PoP DST
	var msgPoint bls12381.G2
	msgPoint.Hash(msg, []byte(DSTProofOfPossession))
	
	// e(pk, H(m)) == e(G1, sig)
	g1Gen := bls12381.G1Generator()
	
	// Prepare for pairing check: e(pk, H(m)) * e(-G1, sig) == 1
	return bls12381.ProdPairFrac(
		[]*bls12381.G1{&pk.point, g1Gen},
		[]*bls12381.G2{&msgPoint, &sig.point},
		[]int{1, -1},
	).IsIdentity()
}

// AggregatePublicKeys2 aggregates multiple public keys
func AggregatePublicKeys2(pks []*DirectPublicKey) (*DirectPublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}
	
	// Start with identity
	aggPk := new(DirectPublicKey)
	aggPk.point.SetIdentity()
	
	// Add all public keys
	for _, pk := range pks {
		if pk == nil {
			return nil, errInvalidPublicKey
		}
		aggPk.point.Add(&aggPk.point, &pk.point)
	}
	
	return aggPk, nil
}

// AggregateSignatures2 aggregates multiple signatures
func AggregateSignatures2(sigs []*DirectSignature) (*DirectSignature, error) {
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}
	
	// Start with identity
	aggSig := new(DirectSignature)
	aggSig.point.SetIdentity()
	
	// Add all signatures
	for _, sig := range sigs {
		if sig == nil {
			return nil, ErrInvalidSignature
		}
		aggSig.point.Add(&aggSig.point, &sig.point)
	}
	
	return aggSig, nil
}

// Serialization methods

// Bytes returns the compressed serialization of the public key
func (pk *DirectPublicKey) Bytes() []byte {
	return pk.point.BytesCompressed()
}

// SetBytes deserializes a public key from compressed bytes
func (pk *DirectPublicKey) SetBytes(data []byte) error {
	return pk.point.SetBytes(data)
}

// Bytes returns the compressed serialization of the signature
func (sig *DirectSignature) Bytes() []byte {
	return sig.point.BytesCompressed()
}

// SetBytes deserializes a signature from compressed bytes
func (sig *DirectSignature) SetBytes(data []byte) error {
	return sig.point.SetBytes(data)
}

// Bytes returns the serialization of the secret key
func (sk *DirectSecretKey) Bytes() []byte {
	// Use MarshalBinary to get the scalar bytes
	data, _ := sk.scalar.MarshalBinary()
	return data
}

// SetBytes deserializes a secret key from bytes
func (sk *DirectSecretKey) SetBytes(data []byte) error {
	if len(data) != 32 {
		return errors.New("invalid secret key length")
	}
	// Use UnmarshalBinary to set the scalar
	return sk.scalar.UnmarshalBinary(data)
}