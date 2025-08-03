// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"crypto/rand"
	"errors"

	blssign "github.com/cloudflare/circl/sign/bls"
)

const (
	SecretKeyLen = 32
	PublicKeyLen = 48 // Compressed G1 point
	SignatureLen = 96 // Compressed G2 point
)

var (
	ErrNoPublicKeys               = errors.New("no public keys")
	ErrFailedPublicKeyDecompress  = errors.New("couldn't decompress public key")
	errInvalidPublicKey           = errors.New("invalid public key")
	errFailedPublicKeyAggregation = errors.New("couldn't aggregate public keys")
	ErrFailedSignatureDecompress  = errors.New("couldn't decompress signature")
	ErrInvalidSignature           = errors.New("invalid signature")
	ErrNoSignatures               = errors.New("no signatures")
	ErrFailedSignatureAggregation = errors.New("couldn't aggregate signatures")
	errFailedSecretKeyDeserialize = errors.New("couldn't deserialize secret key")
)

// Types wrapping the circl BLS types
type (
	SecretKey struct {
		sk *blssign.PrivateKey[blssign.KeyG1SigG2]
	}

	PublicKey struct {
		pk *blssign.PublicKey[blssign.KeyG1SigG2]
	}

	Signature struct {
		sig blssign.Signature
	}

	AggregatePublicKey = PublicKey
	AggregateSignature = Signature
)

// NewSecretKey generates a new secret key from the local source of
// cryptographically secure randomness.
func NewSecretKey() (*SecretKey, error) {
	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	if err != nil {
		return nil, err
	}

	sk, err := blssign.KeyGen[blssign.KeyG1SigG2](ikm, nil, nil)
	if err != nil {
		return nil, err
	}

	// Clear the ikm
	for i := range ikm {
		ikm[i] = 0
	}

	return &SecretKey{sk: sk}, nil
}

// SecretKeyToBytes returns the big-endian format of the secret key.
func SecretKeyToBytes(sk *SecretKey) []byte {
	if sk == nil || sk.sk == nil {
		return nil
	}
	data, _ := sk.sk.MarshalBinary()
	return data
}

// SecretKeyFromBytes parses the big-endian format of the secret key into a
// secret key.
func SecretKeyFromBytes(skBytes []byte) (*SecretKey, error) {
	sk := new(blssign.PrivateKey[blssign.KeyG1SigG2])
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, errFailedSecretKeyDeserialize
	}
	return &SecretKey{sk: sk}, nil
}

// PublicKey returns the public key associated with the secret key.
func (sk *SecretKey) PublicKey() *PublicKey {
	if sk == nil || sk.sk == nil {
		return nil
	}
	return &PublicKey{pk: sk.sk.PublicKey()}
}

// Sign [msg] to authorize that this private key signed [msg].
func (sk *SecretKey) Sign(msg []byte) *Signature {
	if sk == nil || sk.sk == nil {
		return nil
	}
	sig := blssign.Sign(sk.sk, msg)
	return &Signature{sig: sig}
}

// SignProofOfPossession signs a [msg] to prove the ownership of this secret key.
func (sk *SecretKey) SignProofOfPossession(msg []byte) *Signature {
	if sk == nil || sk.sk == nil {
		return nil
	}

	// For now, we have to use regular signing because circl doesn't expose
	// the private key bytes in a way we can extract them
	// TODO: This should use different DST once we have proper access to the key
	sig := blssign.Sign(sk.sk, msg)
	return &Signature{sig: sig}
}

// PublicKeyToCompressedBytes returns the compressed big-endian format of the
// public key.
func PublicKeyToCompressedBytes(pk *PublicKey) []byte {
	if pk == nil || pk.pk == nil {
		return nil
	}
	data, _ := pk.pk.MarshalBinary()
	return data
}

// PublicKeyFromCompressedBytes parses the compressed big-endian format of the
// public key into a public key.
func PublicKeyFromCompressedBytes(pkBytes []byte) (*PublicKey, error) {
	pk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return nil, ErrFailedPublicKeyDecompress
	}

	if !pk.Validate() {
		return nil, errInvalidPublicKey
	}

	return &PublicKey{pk: pk}, nil
}

// PublicKeyToUncompressedBytes returns the uncompressed big-endian format of
// the public key. For circl/bls, this is the same as compressed.
func PublicKeyToUncompressedBytes(key *PublicKey) []byte {
	return PublicKeyToCompressedBytes(key)
}

// PublicKeyFromValidUncompressedBytes parses the uncompressed big-endian format
// of the public key into a public key. It is assumed that the provided bytes
// are valid.
func PublicKeyFromValidUncompressedBytes(pkBytes []byte) *PublicKey {
	pk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	_ = pk.UnmarshalBinary(pkBytes)
	return &PublicKey{pk: pk}
}

// AggregatePublicKeys aggregates a non-zero number of public keys into a single
// aggregated public key.
func AggregatePublicKeys(pks []*PublicKey) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}

	// Convert to our internal representation that can access G1 points
	newPks := make([]*DirectPublicKey, len(pks))
	for i, pk := range pks {
		if pk == nil || pk.pk == nil {
			return nil, errInvalidPublicKey
		}

		// Get the compressed bytes from the circl public key
		pkBytes, err := pk.pk.MarshalBinary()
		if err != nil {
			return nil, errFailedPublicKeyAggregation
		}

		// Create a new public key with direct G1 access
		newPk := new(DirectPublicKey)
		if err := newPk.SetBytes(pkBytes); err != nil {
			return nil, errFailedPublicKeyAggregation
		}
		newPks[i] = newPk
	}

	// Aggregate using our implementation
	aggNewPk, err := AggregatePublicKeys2(newPks)
	if err != nil {
		return nil, err
	}

	// Convert back to circl PublicKey type
	aggPkBytes := aggNewPk.Bytes()
	aggPk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := aggPk.UnmarshalBinary(aggPkBytes); err != nil {
		return nil, errFailedPublicKeyAggregation
	}

	return &PublicKey{pk: aggPk}, nil
}

// Verify the [sig] of [msg] against the [pk].
func Verify(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil {
		return false
	}

	return blssign.Verify(pk.pk, msg, sig.sig)
}

// VerifyProofOfPossession verifies the possession of the secret pre-image of [sk]
func VerifyProofOfPossession(pk *PublicKey, sig *Signature, msg []byte) bool {
	// TODO: This should use different DST from regular Verify
	// For now, it's the same as Verify due to circl library limitations
	return Verify(pk, sig, msg)
}

// SignatureToBytes returns the compressed big-endian format of the signature.
func SignatureToBytes(sig *Signature) []byte {
	if sig == nil {
		return nil
	}
	return sig.sig
}

// SignatureFromBytes parses the compressed big-endian format of the signature
// into a signature.
func SignatureFromBytes(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != SignatureLen {
		return nil, ErrFailedSignatureDecompress
	}

	// Check if signature is all zeros (invalid)
	allZero := true
	for _, b := range sigBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, ErrInvalidSignature
	}

	return &Signature{sig: sigBytes}, nil
}

// AggregateSignatures aggregates a non-zero number of signatures into a single
// aggregated signature.
func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	// Convert to slice of Signature bytes
	sigBytes := make([]blssign.Signature, len(sigs))
	for i, sig := range sigs {
		if sig == nil {
			return nil, ErrFailedSignatureAggregation
		}
		sigBytes[i] = sig.sig
	}

	// Use the Aggregate function from circl
	aggSig, err := blssign.Aggregate[blssign.KeyG1SigG2](blssign.KeyG1SigG2{}, sigBytes)
	if err != nil {
		return nil, ErrFailedSignatureAggregation
	}

	return &Signature{sig: aggSig}, nil
}
