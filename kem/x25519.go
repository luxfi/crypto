package kem

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// X25519Impl implements X25519 as a KEM
type X25519Impl struct{}

// NewX25519 creates a new X25519 KEM instance
func NewX25519() KEM {
	return &X25519Impl{}
}

// X25519PublicKey represents an X25519 public key
type X25519PublicKey struct {
	data [32]byte
}

// X25519PrivateKey represents an X25519 private key  
type X25519PrivateKey struct {
	data [32]byte
	pk   *X25519PublicKey
}

// GenerateKeyPair generates a new X25519 key pair
func (x *X25519Impl) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	sk := &X25519PrivateKey{}
	
	// Generate random private key
	if _, err := rand.Read(sk.data[:]); err != nil {
		return nil, nil, err
	}
	
	// Clamp private key as per X25519 spec
	sk.data[0] &= 248
	sk.data[31] &= 127
	sk.data[31] |= 64
	
	// Compute public key
	pk := &X25519PublicKey{}
	curve25519.ScalarBaseMult(&pk.data, &sk.data)
	sk.pk = pk
	
	return pk, sk, nil
}

// Encapsulate generates ephemeral key and shared secret
func (x *X25519Impl) Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	x25519PK, ok := pk.(*X25519PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type for X25519")
	}
	
	// Generate ephemeral key pair
	ephSK := &X25519PrivateKey{}
	if _, err := rand.Read(ephSK.data[:]); err != nil {
		return nil, nil, err
	}
	
	// Clamp ephemeral private key
	ephSK.data[0] &= 248
	ephSK.data[31] &= 127
	ephSK.data[31] |= 64
	
	// Compute ephemeral public key (ciphertext)
	ephPK := &X25519PublicKey{}
	curve25519.ScalarBaseMult(&ephPK.data, &ephSK.data)
	
	// Compute shared secret
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &ephSK.data, &x25519PK.data)
	
	// Check for low-order points
	if isLowOrder(sharedSecret[:]) {
		return nil, nil, errors.New("low-order shared secret")
	}
	
	return ephPK.data[:], sharedSecret[:], nil
}

// Decapsulate recovers shared secret using private key
func (x *X25519Impl) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	x25519SK, ok := sk.(*X25519PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for X25519")
	}
	
	if len(ciphertext) != 32 {
		return nil, errors.New("invalid ciphertext size for X25519")
	}
	
	var ephPK [32]byte
	copy(ephPK[:], ciphertext)
	
	// Compute shared secret
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &x25519SK.data, &ephPK)
	
	// Check for low-order points
	if isLowOrder(sharedSecret[:]) {
		return nil, errors.New("low-order shared secret")
	}
	
	return sharedSecret[:], nil
}

// isLowOrder checks if the point is low-order
func isLowOrder(p []byte) bool {
	// Check against known low-order points
	var allZero [32]byte
	return subtle.ConstantTimeCompare(p, allZero[:]) == 1
}

// Size methods for X25519
func (x *X25519Impl) PublicKeySize() int   { return 32 }
func (x *X25519Impl) PrivateKeySize() int  { return 32 }
func (x *X25519Impl) CiphertextSize() int  { return 32 }
func (x *X25519Impl) SharedSecretSize() int { return 32 }

// Bytes returns the public key bytes
func (pk *X25519PublicKey) Bytes() []byte {
	return pk.data[:]
}

// Equal checks if two public keys are equal
func (pk *X25519PublicKey) Equal(other PublicKey) bool {
	otherPK, ok := other.(*X25519PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pk.data[:], otherPK.data[:]) == 1
}

// Bytes returns the private key bytes
func (sk *X25519PrivateKey) Bytes() []byte {
	return sk.data[:]
}

// Public returns the public key
func (sk *X25519PrivateKey) Public() PublicKey {
	return sk.pk
}

// Equal checks if two private keys are equal
func (sk *X25519PrivateKey) Equal(other PrivateKey) bool {
	otherSK, ok := other.(*X25519PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(sk.data[:], otherSK.data[:]) == 1
}