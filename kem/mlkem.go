package kem

// Pure Go implementation of ML-KEM using crypto/mlkem from the Go standard library (FIPS 203).
// When CGO is enabled and liboqs is installed, the optimized versions in mlkem_c.go are used instead.

import (
	"crypto/mlkem"
	"crypto/subtle"
	"errors"
	"fmt"
)

// MLKEM768Impl implements ML-KEM-768 using Go's crypto/mlkem (FIPS 203)
type MLKEM768Impl struct{}

// MLKEM768PublicKey represents an ML-KEM-768 encapsulation key
type MLKEM768PublicKey struct {
	data []byte
}

// MLKEM768PrivateKey represents an ML-KEM-768 decapsulation key (seed form)
type MLKEM768PrivateKey struct {
	data []byte
	pk   *MLKEM768PublicKey
}

// GenerateKeyPair generates a new ML-KEM-768 key pair using crypto/mlkem.
func (m *MLKEM768Impl) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}

	ekBytes := dk.EncapsulationKey().Bytes()
	dkBytes := dk.Bytes()

	pk := &MLKEM768PublicKey{data: ekBytes}
	sk := &MLKEM768PrivateKey{data: dkBytes, pk: pk}
	return pk, sk, nil
}

// Encapsulate generates a shared secret and ciphertext from an encapsulation key.
func (m *MLKEM768Impl) Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	mlkemPK, ok := pk.(*MLKEM768PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type")
	}

	ek, err := mlkem.NewEncapsulationKey768(mlkemPK.data)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, ciphertext := ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using the decapsulation key.
func (m *MLKEM768Impl) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	mlkemSK, ok := sk.(*MLKEM768PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}

	if len(ciphertext) != mlkem.CiphertextSize768 {
		return nil, errors.New("invalid ciphertext size")
	}

	dk, err := mlkem.NewDecapsulationKey768(mlkemSK.data)
	if err != nil {
		return nil, err
	}

	return dk.Decapsulate(ciphertext)
}

// PublicKeySize returns the size of ML-KEM-768 encapsulation keys.
func (m *MLKEM768Impl) PublicKeySize() int { return mlkem.EncapsulationKeySize768 }

// PrivateKeySize returns the size of ML-KEM-768 decapsulation key seeds.
func (m *MLKEM768Impl) PrivateKeySize() int { return mlkem.SeedSize }

// CiphertextSize returns the size of ML-KEM-768 ciphertexts.
func (m *MLKEM768Impl) CiphertextSize() int { return mlkem.CiphertextSize768 }

// SharedSecretSize returns the size of ML-KEM-768 shared secrets.
func (m *MLKEM768Impl) SharedSecretSize() int { return mlkem.SharedKeySize }

// ParseMLKEM768PublicKey reconstructs an MLKEM768PublicKey from raw encapsulation key bytes.
func ParseMLKEM768PublicKey(data []byte) (*MLKEM768PublicKey, error) {
	if len(data) != mlkem.EncapsulationKeySize768 {
		return nil, fmt.Errorf("invalid ML-KEM-768 public key size: got %d, expected %d", len(data), mlkem.EncapsulationKeySize768)
	}
	// Validate by attempting to construct the Go stdlib encapsulation key
	if _, err := mlkem.NewEncapsulationKey768(data); err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 public key: %w", err)
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return &MLKEM768PublicKey{data: cp}, nil
}

// Bytes returns the raw bytes of the public key.
func (pk *MLKEM768PublicKey) Bytes() []byte { return pk.data }

// Equal checks if two public keys are equal in constant time.
func (pk *MLKEM768PublicKey) Equal(other PublicKey) bool {
	otherPK, ok := other.(*MLKEM768PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pk.data, otherPK.data) == 1
}

// Bytes returns the raw bytes of the private key seed.
func (sk *MLKEM768PrivateKey) Bytes() []byte { return sk.data }

// Public returns the public key corresponding to the private key.
func (sk *MLKEM768PrivateKey) Public() PublicKey { return sk.pk }

// Equal checks if two private keys are equal in constant time.
func (sk *MLKEM768PrivateKey) Equal(other PrivateKey) bool {
	otherSK, ok := other.(*MLKEM768PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(sk.data, otherSK.data) == 1
}

// MLKEM1024Impl implements ML-KEM-1024 using Go's crypto/mlkem (FIPS 203)
type MLKEM1024Impl struct{}

// MLKEM1024PublicKey represents an ML-KEM-1024 encapsulation key
type MLKEM1024PublicKey struct {
	data []byte
}

// MLKEM1024PrivateKey represents an ML-KEM-1024 decapsulation key (seed form)
type MLKEM1024PrivateKey struct {
	data []byte
	pk   *MLKEM1024PublicKey
}

// GenerateKeyPair generates a new ML-KEM-1024 key pair using crypto/mlkem.
func (m *MLKEM1024Impl) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}

	ekBytes := dk.EncapsulationKey().Bytes()
	dkBytes := dk.Bytes()

	pk := &MLKEM1024PublicKey{data: ekBytes}
	sk := &MLKEM1024PrivateKey{data: dkBytes, pk: pk}
	return pk, sk, nil
}

// Encapsulate generates a shared secret and ciphertext from an encapsulation key.
func (m *MLKEM1024Impl) Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	mlkemPK, ok := pk.(*MLKEM1024PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type")
	}

	ek, err := mlkem.NewEncapsulationKey1024(mlkemPK.data)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, ciphertext := ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using the decapsulation key.
func (m *MLKEM1024Impl) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	mlkemSK, ok := sk.(*MLKEM1024PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}

	if len(ciphertext) != mlkem.CiphertextSize1024 {
		return nil, errors.New("invalid ciphertext size")
	}

	dk, err := mlkem.NewDecapsulationKey1024(mlkemSK.data)
	if err != nil {
		return nil, err
	}

	return dk.Decapsulate(ciphertext)
}

// PublicKeySize returns the size of ML-KEM-1024 encapsulation keys.
func (m *MLKEM1024Impl) PublicKeySize() int { return mlkem.EncapsulationKeySize1024 }

// PrivateKeySize returns the size of ML-KEM-1024 decapsulation key seeds.
func (m *MLKEM1024Impl) PrivateKeySize() int { return mlkem.SeedSize }

// CiphertextSize returns the size of ML-KEM-1024 ciphertexts.
func (m *MLKEM1024Impl) CiphertextSize() int { return mlkem.CiphertextSize1024 }

// SharedSecretSize returns the size of ML-KEM-1024 shared secrets.
func (m *MLKEM1024Impl) SharedSecretSize() int { return mlkem.SharedKeySize }

// Bytes returns the raw bytes of the public key.
func (pk *MLKEM1024PublicKey) Bytes() []byte { return pk.data }

// Equal checks if two public keys are equal in constant time.
func (pk *MLKEM1024PublicKey) Equal(other PublicKey) bool {
	otherPK, ok := other.(*MLKEM1024PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pk.data, otherPK.data) == 1
}

// Bytes returns the raw bytes of the private key seed.
func (sk *MLKEM1024PrivateKey) Bytes() []byte { return sk.data }

// Public returns the public key corresponding to the private key.
func (sk *MLKEM1024PrivateKey) Public() PublicKey { return sk.pk }

// Equal checks if two private keys are equal in constant time.
func (sk *MLKEM1024PrivateKey) Equal(other PrivateKey) bool {
	otherSK, ok := other.(*MLKEM1024PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(sk.data, otherSK.data) == 1
}
