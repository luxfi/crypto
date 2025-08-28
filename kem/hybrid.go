package kem

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HybridKEMImpl implements hybrid X25519 + ML-KEM-768
type HybridKEMImpl struct {
	x25519 KEM
	mlkem  KEM
}

// NewHybridKEM creates a new hybrid KEM instance
func NewHybridKEM() KEM {
	// Note: For now using the direct constructors that return KEM
	// In production, this should handle errors properly
	return &HybridKEMImpl{
		x25519: &X25519Impl{},
		mlkem:  &MLKEM768Impl{k: 3},
	}
}

// HybridPublicKey contains both X25519 and ML-KEM public keys
type HybridPublicKey struct {
	X25519PK PublicKey
	MLKEMPK  PublicKey
}

// HybridPrivateKey contains both X25519 and ML-KEM private keys
type HybridPrivateKey struct {
	X25519SK PrivateKey
	MLKEMSK  PrivateKey
}

// GenerateKeyPair generates a hybrid key pair
func (h *HybridKEMImpl) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	x25519PK, x25519SK, err := h.x25519.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	
	mlkemPK, mlkemSK, err := h.mlkem.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	
	pk := &HybridPublicKey{
		X25519PK: x25519PK,
		MLKEMPK:  mlkemPK,
	}
	
	sk := &HybridPrivateKey{
		X25519SK: x25519SK,
		MLKEMSK:  mlkemSK,
	}
	
	return pk, sk, nil
}

// Encapsulate performs hybrid encapsulation
func (h *HybridKEMImpl) Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	hybridPK, ok := pk.(*HybridPublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type for hybrid KEM")
	}
	
	// Perform X25519 encapsulation
	x25519CT, x25519SS, err := h.x25519.Encapsulate(hybridPK.X25519PK)
	if err != nil {
		return nil, nil, err
	}
	
	// Perform ML-KEM encapsulation
	mlkemCT, mlkemSS, err := h.mlkem.Encapsulate(hybridPK.MLKEMPK)
	if err != nil {
		return nil, nil, err
	}
	
	// Concatenate ciphertexts
	ciphertext := append(x25519CT, mlkemCT...)
	
	// Derive shared secret using HKDF
	sharedSecret := h.deriveSharedSecret(x25519SS, mlkemSS)
	
	return ciphertext, sharedSecret, nil
}

// Decapsulate performs hybrid decapsulation
func (h *HybridKEMImpl) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	hybridSK, ok := sk.(*HybridPrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for hybrid KEM")
	}
	
	x25519CTSize := h.x25519.CiphertextSize()
	if len(ciphertext) < x25519CTSize {
		return nil, errors.New("ciphertext too short")
	}
	
	// Split ciphertext
	x25519CT := ciphertext[:x25519CTSize]
	mlkemCT := ciphertext[x25519CTSize:]
	
	// Perform X25519 decapsulation
	x25519SS, err := h.x25519.Decapsulate(hybridSK.X25519SK, x25519CT)
	if err != nil {
		return nil, err
	}
	
	// Perform ML-KEM decapsulation
	mlkemSS, err := h.mlkem.Decapsulate(hybridSK.MLKEMSK, mlkemCT)
	if err != nil {
		return nil, err
	}
	
	// Derive shared secret using HKDF
	sharedSecret := h.deriveSharedSecret(x25519SS, mlkemSS)
	
	return sharedSecret, nil
}

// deriveSharedSecret combines secrets using HKDF-SHA256
func (h *HybridKEMImpl) deriveSharedSecret(x25519SS, mlkemSS []byte) []byte {
	// Concatenate secrets
	combined := append(x25519SS, mlkemSS...)
	
	// Use HKDF-Extract then Expand
	salt := []byte("QZMQ-HybridKEM-v1")
	info := []byte("hybrid-kem-shared-secret")
	
	hkdf := hkdf.New(sha256.New, combined, salt, info)
	sharedSecret := make([]byte, 32)
	
	if _, err := io.ReadFull(hkdf, sharedSecret); err != nil {
		panic(err) // Should never happen with correct sizes
	}
	
	return sharedSecret
}

// Size methods for hybrid KEM
func (h *HybridKEMImpl) PublicKeySize() int {
	return h.x25519.PublicKeySize() + h.mlkem.PublicKeySize()
}

func (h *HybridKEMImpl) PrivateKeySize() int {
	return h.x25519.PrivateKeySize() + h.mlkem.PrivateKeySize()
}

func (h *HybridKEMImpl) CiphertextSize() int {
	return h.x25519.CiphertextSize() + h.mlkem.CiphertextSize()
}

func (h *HybridKEMImpl) SharedSecretSize() int {
	return 32 // HKDF output size
}

// Bytes returns the concatenated public key bytes
func (pk *HybridPublicKey) Bytes() []byte {
	return append(pk.X25519PK.Bytes(), pk.MLKEMPK.Bytes()...)
}

// Equal checks if two hybrid public keys are equal
func (pk *HybridPublicKey) Equal(other PublicKey) bool {
	otherPK, ok := other.(*HybridPublicKey)
	if !ok {
		return false
	}
	return pk.X25519PK.Equal(otherPK.X25519PK) && pk.MLKEMPK.Equal(otherPK.MLKEMPK)
}

// Bytes returns the concatenated private key bytes
func (sk *HybridPrivateKey) Bytes() []byte {
	return append(sk.X25519SK.Bytes(), sk.MLKEMSK.Bytes()...)
}

// Public returns the hybrid public key
func (sk *HybridPrivateKey) Public() PublicKey {
	return &HybridPublicKey{
		X25519PK: sk.X25519SK.Public(),
		MLKEMPK:  sk.MLKEMSK.Public(),
	}
}

// Equal checks if two hybrid private keys are equal
func (sk *HybridPrivateKey) Equal(other PrivateKey) bool {
	otherSK, ok := other.(*HybridPrivateKey)
	if !ok {
		return false
	}
	return sk.X25519SK.Equal(otherSK.X25519SK) && sk.MLKEMSK.Equal(otherSK.MLKEMSK)
}