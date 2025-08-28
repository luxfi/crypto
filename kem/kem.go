// Package kem provides post-quantum Key Encapsulation Mechanisms
package kem

import (
	"fmt"
)

// KemID identifies a KEM algorithm
type KemID string

const (
	MLKEM768  KemID = "mlkem768"
	MLKEM1024 KemID = "mlkem1024"
	X25519    KemID = "x25519"
	HybridKEM KemID = "x25519+mlkem768"
)

// KEM interface for key encapsulation mechanisms
type KEM interface {
	// GenerateKeyPair generates a new KEM key pair
	GenerateKeyPair() (PublicKey, PrivateKey, error)
	
	// Encapsulate generates a shared secret and ciphertext
	Encapsulate(pk PublicKey) (ciphertext []byte, sharedSecret []byte, err error)
	
	// Decapsulate recovers the shared secret from ciphertext
	Decapsulate(sk PrivateKey, ciphertext []byte) (sharedSecret []byte, err error)
	
	// PublicKeySize returns the size of public keys
	PublicKeySize() int
	
	// PrivateKeySize returns the size of private keys
	PrivateKeySize() int
	
	// CiphertextSize returns the size of ciphertexts
	CiphertextSize() int
	
	// SharedSecretSize returns the size of shared secrets
	SharedSecretSize() int
}

// PublicKey represents a KEM public key
type PublicKey interface {
	Bytes() []byte
	Equal(PublicKey) bool
}

// PrivateKey represents a KEM private key
type PrivateKey interface {
	Bytes() []byte
	Public() PublicKey
	Equal(PrivateKey) bool
}

// Constants for ML-KEM-768
const (
	mlkem768PublicKeySize     = 1184
	mlkem768PrivateKeySize    = 2400
	mlkem768CiphertextSize    = 1088
	mlkem768SharedSecretSize  = 32
)

// Constants for ML-KEM-1024
const (
	mlkem1024PublicKeySize    = 1568
	mlkem1024PrivateKeySize   = 3168
	mlkem1024CiphertextSize   = 1568
	mlkem1024SharedSecretSize = 32
)

// GetKEM returns a KEM implementation for the given ID
func GetKEM(id KemID) (KEM, error) {
	switch id {
	case MLKEM768:
		return NewMLKEM768()
	case MLKEM1024:
		return NewMLKEM1024()
	case X25519:
		return NewX25519Factory()
	case HybridKEM:
		return NewHybrid()
	default:
		return nil, fmt.Errorf("unsupported KEM: %s", id)
	}
}