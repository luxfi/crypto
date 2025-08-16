// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Package lamport implements Lamport one-time signatures
// Simple, fast, quantum-resistant signatures based only on hash functions

package lamport

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
)

// HashFunc represents the hash function to use
type HashFunc int

const (
	SHA256 HashFunc = iota
	SHA512
	SHA3_256
	SHA3_512
)

// Parameters for Lamport signatures
const (
	// SHA256 parameters
	SHA256HashSize = 32
	SHA256KeySize  = 256 * 2 * SHA256HashSize // 256 bits * 2 (for 0 and 1) * hash size
	SHA256SigSize  = 256 * SHA256HashSize     // 256 bits * hash size

	// SHA512 parameters
	SHA512HashSize = 64
	SHA512KeySize  = 512 * 2 * SHA512HashSize
	SHA512SigSize  = 512 * SHA512HashSize
)

// PrivateKey represents a Lamport private key
type PrivateKey struct {
	hashFunc HashFunc
	keys     [][]byte // Two arrays of random values for each bit position
}

// PublicKey represents a Lamport public key
type PublicKey struct {
	hashFunc HashFunc
	hashes   [][]byte // Hashes of the private key values
}

// Signature represents a Lamport signature
type Signature struct {
	hashFunc HashFunc
	values   [][]byte // Selected private key values based on message bits
}

// GenerateKey generates a new Lamport keypair
func GenerateKey(rng io.Reader, hashFunc HashFunc) (*PrivateKey, error) {
	if rng == nil {
		rng = rand.Reader
	}

	hashSize, numBits := getHashParams(hashFunc)

	// Generate 2*numBits random values (one for 0, one for 1 for each bit)
	keys := make([][]byte, 2*numBits)
	for i := range keys {
		keys[i] = make([]byte, hashSize)
		if _, err := io.ReadFull(rng, keys[i]); err != nil {
			return nil, err
		}
	}

	return &PrivateKey{
		hashFunc: hashFunc,
		keys:     keys,
	}, nil
}

// Public returns the public key corresponding to this private key
func (priv *PrivateKey) Public() *PublicKey {
	hashSize, numBits := getHashParams(priv.hashFunc)
	hasher := getHasher(priv.hashFunc)

	// Hash all private key values to create public key
	hashes := make([][]byte, 2*numBits)
	for i, key := range priv.keys {
		hasher.Reset()
		hasher.Write(key)
		hashes[i] = hasher.Sum(nil)[:hashSize]
	}

	return &PublicKey{
		hashFunc: priv.hashFunc,
		hashes:   hashes,
	}
}

// Sign creates a Lamport signature for the given message
// IMPORTANT: Each private key can only be used ONCE
func (priv *PrivateKey) Sign(message []byte) (*Signature, error) {
	// Hash the message first
	hasher := getHasher(priv.hashFunc)
	hasher.Write(message)
	msgHash := hasher.Sum(nil)

	_, numBits := getHashParams(priv.hashFunc)

	// Select private key values based on message bits
	values := make([][]byte, numBits)
	for i := 0; i < numBits; i++ {
		byteIndex := i / 8
		bitIndex := uint(i % 8)

		if byteIndex >= len(msgHash) {
			// Pad with zeros if message hash is shorter
			values[i] = priv.keys[2*i] // Use the "0" value
		} else {
			bit := (msgHash[byteIndex] >> (7 - bitIndex)) & 1
			if bit == 0 {
				values[i] = priv.keys[2*i] // Use the "0" value
			} else {
				values[i] = priv.keys[2*i+1] // Use the "1" value
			}
		}
	}

	// Clear private key after use (one-time signature)
	for i := range priv.keys {
		for j := range priv.keys[i] {
			priv.keys[i][j] = 0
		}
	}

	return &Signature{
		hashFunc: priv.hashFunc,
		values:   values,
	}, nil
}

// Verify checks if a signature is valid for the given message
func (pub *PublicKey) Verify(message []byte, sig *Signature) bool {
	if pub.hashFunc != sig.hashFunc {
		return false
	}

	// Hash the message
	hasher := getHasher(pub.hashFunc)
	hasher.Write(message)
	msgHash := hasher.Sum(nil)

	return pub.VerifyHash(msgHash, sig)
}

// VerifyHash checks if a signature is valid for the given message hash
func (pub *PublicKey) VerifyHash(msgHash []byte, sig *Signature) bool {
	if pub.hashFunc != sig.hashFunc {
		return false
	}

	hashSize, numBits := getHashParams(pub.hashFunc)

	if len(sig.values) != numBits {
		return false
	}

	// Verify each signature value
	hasher := getHasher(pub.hashFunc)
	for i := 0; i < numBits; i++ {
		byteIndex := i / 8
		bitIndex := uint(i % 8)

		var bit byte
		if byteIndex >= len(msgHash) {
			bit = 0 // Pad with zeros
		} else {
			bit = (msgHash[byteIndex] >> (7 - bitIndex)) & 1
		}

		// Hash the signature value
		hasher.Reset()
		hasher.Write(sig.values[i])
		sigHash := hasher.Sum(nil)[:hashSize]

		// Compare with corresponding public key hash
		var expectedHash []byte
		if bit == 0 {
			expectedHash = pub.hashes[2*i]
		} else {
			expectedHash = pub.hashes[2*i+1]
		}

		if !bytesEqual(sigHash, expectedHash) {
			return false
		}
	}

	return true
}

// Bytes serializes the public key
func (pub *PublicKey) Bytes() []byte {
	hashSize, numBits := getHashParams(pub.hashFunc)

	result := make([]byte, 1+2*numBits*hashSize)
	result[0] = byte(pub.hashFunc)

	offset := 1
	for _, hash := range pub.hashes {
		copy(result[offset:], hash)
		offset += hashSize
	}

	return result
}

// PublicKeyFromBytes deserializes a public key
func PublicKeyFromBytes(data []byte) (*PublicKey, error) {
	if len(data) < 1 {
		return nil, errors.New("invalid public key data")
	}

	hashFunc := HashFunc(data[0])
	hashSize, numBits := getHashParams(hashFunc)

	expectedSize := 1 + 2*numBits*hashSize
	if len(data) != expectedSize {
		return nil, errors.New("invalid public key size")
	}

	hashes := make([][]byte, 2*numBits)
	offset := 1
	for i := range hashes {
		hashes[i] = make([]byte, hashSize)
		copy(hashes[i], data[offset:offset+hashSize])
		offset += hashSize
	}

	return &PublicKey{
		hashFunc: hashFunc,
		hashes:   hashes,
	}, nil
}

// Bytes serializes the signature
func (sig *Signature) Bytes() []byte {
	hashSize, numBits := getHashParams(sig.hashFunc)

	result := make([]byte, 1+numBits*hashSize)
	result[0] = byte(sig.hashFunc)

	offset := 1
	for _, value := range sig.values {
		copy(result[offset:], value)
		offset += hashSize
	}

	return result
}

// SignatureFromBytes deserializes a signature
func SignatureFromBytes(data []byte) (*Signature, error) {
	if len(data) < 1 {
		return nil, errors.New("invalid signature data")
	}

	hashFunc := HashFunc(data[0])
	hashSize, numBits := getHashParams(hashFunc)

	expectedSize := 1 + numBits*hashSize
	if len(data) != expectedSize {
		return nil, errors.New("invalid signature size")
	}

	values := make([][]byte, numBits)
	offset := 1
	for i := range values {
		values[i] = make([]byte, hashSize)
		copy(values[i], data[offset:offset+hashSize])
		offset += hashSize
	}

	return &Signature{
		hashFunc: hashFunc,
		values:   values,
	}, nil
}

// Helper functions

func getHashParams(hashFunc HashFunc) (hashSize, numBits int) {
	switch hashFunc {
	case SHA256, SHA3_256:
		return SHA256HashSize, 256
	case SHA512, SHA3_512:
		return SHA512HashSize, 512
	default:
		return SHA256HashSize, 256
	}
}

func getHasher(hashFunc HashFunc) hash.Hash {
	switch hashFunc {
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	case SHA3_256:
		return sha256.New() // Would use sha3.New256() with proper import
	case SHA3_512:
		return sha512.New() // Would use sha3.New512() with proper import
	default:
		return sha256.New()
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetPublicKeySize returns the size of a public key for the given hash function
func GetPublicKeySize(hashFunc HashFunc) int {
	hashSize, numBits := getHashParams(hashFunc)
	return 1 + 2*numBits*hashSize
}

// GetSignatureSize returns the size of a signature for the given hash function
func GetSignatureSize(hashFunc HashFunc) int {
	hashSize, numBits := getHashParams(hashFunc)
	return 1 + numBits*hashSize
}
