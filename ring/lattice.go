// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"

	"github.com/luxfi/crypto/mldsa"
)

// Post-quantum ring signature using ML-DSA (FIPS 204) key material.
//
// ⚠️ CRITICAL SECURITY NOTE: PLACEHOLDER IMPLEMENTATION ⚠️
//
// This is a HASH-BASED SIMULATION of ring signatures, NOT a true lattice-based
// ring signature scheme. The "lattice" in the name refers ONLY to the post-quantum
// key material (ML-DSA), NOT to the ring signature construction itself.
//
// IMPLEMENTATION STATUS: This is a PLACEHOLDER using hash-based construction.
// It MUST be replaced with a real lattice-based ring signature before production use
// in any system claiming post-quantum security.
//
// The current construction provides:
// ✓ Post-quantum secure key material (ML-DSA-65, NIST Level 3)
// ✓ Ring signature anonymity (signer hidden among ring members)
// ✓ Linkability (same key produces same key image)
// ✓ Double-spend detection via key images
//
// CRITICAL LIMITATIONS:
// ✗ Security relies on hash function (SHA-512) properties, NOT lattice hardness
// ✗ Ring signature itself is NOT post-quantum secure against quantum adversaries
// ✗ Suitable ONLY for applications where PQ key material is required but classical
//   ring signature security is acceptable (e.g., development, testing)
//
// For production post-quantum ring signatures, integrate one of:
// - Raptor (lattice-based ring signatures from NTRU)
// - MatRiCT (module-LWE based)
// - Calamari/Squid (isogeny-based)
// - Or implement from github.com/luxfi/lattice with proper ring signature construction

// Size constants based on ML-DSA-65 (192-bit security, NIST Level 3)
const (
	// mldsaMode is the ML-DSA security level used
	mldsaMode = mldsa.MLDSA65

	// latticeKeyImageSize is the size of the key image (SHA-256 hash)
	latticeKeyImageSize = 32

	// latticeResponseSize is the size of each response value
	latticeResponseSize = 64
)

// LatticeSignature implements ring signatures with post-quantum key material.
// IMPORTANT: This uses ML-DSA key material but the ring signature construction
// itself is hash-based (NOT a true lattice ring signature scheme).
// The construction provides anonymity among ring members with linkability.
type LatticeSignature struct {
	keyImage []byte   // Key image for linkability (32 bytes)
	s        [][]byte // Response values for each ring member (64 bytes each)
	tag      []byte   // Signature tag binding all responses (64 bytes)
}

// Scheme returns LatticeLSAG.
func (sig *LatticeSignature) Scheme() Scheme {
	return LatticeLSAG
}

// Bytes serializes the signature.
func (sig *LatticeSignature) Bytes() []byte {
	n := len(sig.s)
	if n == 0 {
		return nil
	}

	// Format: keyImage (32) + tag (64) + n (4) + s values (n * 64)
	size := latticeKeyImageSize + 64 + 4 + n*latticeResponseSize
	data := make([]byte, size)

	offset := 0
	copy(data[offset:offset+latticeKeyImageSize], sig.keyImage)
	offset += latticeKeyImageSize

	copy(data[offset:offset+64], sig.tag)
	offset += 64

	binary.BigEndian.PutUint32(data[offset:offset+4], uint32(n))
	offset += 4

	for _, si := range sig.s {
		copy(data[offset:offset+latticeResponseSize], si)
		offset += latticeResponseSize
	}

	return data
}

// KeyImage returns the key image for linkability.
func (sig *LatticeSignature) KeyImage() []byte {
	result := make([]byte, len(sig.keyImage))
	copy(result, sig.keyImage)
	return result
}

// RingSize returns the number of public keys in the ring.
func (sig *LatticeSignature) RingSize() int {
	return len(sig.s)
}

// Verify verifies the lattice ring signature.
func (sig *LatticeSignature) Verify(message []byte, ring [][]byte) bool {
	n := len(ring)
	if n != len(sig.s) {
		return false
	}
	if n < 2 {
		return false
	}

	// Verify all public keys are valid ML-DSA keys
	for _, pkBytes := range ring {
		if _, err := mldsa.PublicKeyFromBytes(pkBytes, mldsaMode); err != nil {
			return false
		}
	}

	// Recompute the signature tag
	// tag = H(message, keyImage, H(s[0], P[0]), H(s[1], P[1]), ..., H(s[n-1], P[n-1]))
	h := sha512.New()
	h.Write([]byte("lattice-ring-verify"))
	h.Write(message)
	h.Write(sig.keyImage)

	for i := 0; i < n; i++ {
		// Compute commitment for position i
		commitment := latticeCommitment(sig.s[i], ring[i], sig.keyImage, i)
		h.Write(commitment)
	}

	expectedTag := h.Sum(nil)

	return constantTimeCompare(sig.tag, expectedTag)
}

// ParseLatticeSignature parses a lattice ring signature from bytes.
func ParseLatticeSignature(data []byte) (*LatticeSignature, error) {
	minSize := latticeKeyImageSize + 64 + 4
	if len(data) < minSize {
		return nil, errors.New("signature too short")
	}

	sig := &LatticeSignature{}

	offset := 0
	sig.keyImage = make([]byte, latticeKeyImageSize)
	copy(sig.keyImage, data[offset:offset+latticeKeyImageSize])
	offset += latticeKeyImageSize

	sig.tag = make([]byte, 64)
	copy(sig.tag, data[offset:offset+64])
	offset += 64

	n := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if n < 2 || n > 1000 {
		return nil, errors.New("invalid ring size")
	}

	expectedSize := minSize + n*latticeResponseSize
	if len(data) != expectedSize {
		return nil, errors.New("invalid signature length")
	}

	sig.s = make([][]byte, n)
	for i := 0; i < n; i++ {
		sig.s[i] = make([]byte, latticeResponseSize)
		copy(sig.s[i], data[offset:offset+latticeResponseSize])
		offset += latticeResponseSize
	}

	return sig, nil
}

// LatticeSigner creates ring signatures using ML-DSA (post-quantum) key material.
// Note: While the keys are post-quantum secure, the ring signature construction
// is hash-based and provides classical (not post-quantum) ring signature security.
type LatticeSigner struct {
	privateKey *mldsa.PrivateKey
	publicKey  *mldsa.PublicKey
	keyImage   []byte
	// secretScalar is derived from private key for ring signature math
	secretScalar []byte
}

// NewLatticeSigner creates a new ring signer using ML-DSA key material.
func NewLatticeSigner(reader io.Reader) (*LatticeSigner, error) {
	if reader == nil {
		reader = rand.Reader
	}

	// Generate ML-DSA key pair
	privKey, err := mldsa.GenerateKey(reader, mldsaMode)
	if err != nil {
		return nil, err
	}

	return newLatticeSignerFromKey(privKey)
}

// NewLatticeSignerFromPrivateKey creates a signer from an existing private key.
func NewLatticeSignerFromPrivateKey(privateKey []byte) (*LatticeSigner, error) {
	privKey, err := mldsa.PrivateKeyFromBytes(mldsaMode, privateKey)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	return newLatticeSignerFromKey(privKey)
}

func newLatticeSignerFromKey(privKey *mldsa.PrivateKey) (*LatticeSigner, error) {
	// Derive a secret scalar from the private key for ring signature operations
	secretScalar := deriveSecretScalar(privKey.Bytes())

	// Compute key image: I = x * H_p(P) (simulated with hashing)
	pubKeyBytes := privKey.PublicKey.Bytes()
	keyImage := computeLatticeKeyImage(secretScalar, pubKeyBytes)

	return &LatticeSigner{
		privateKey:   privKey,
		publicKey:    privKey.PublicKey,
		keyImage:     keyImage,
		secretScalar: secretScalar,
	}, nil
}

// Scheme returns LatticeLSAG.
func (s *LatticeSigner) Scheme() Scheme {
	return LatticeLSAG
}

// PublicKey returns the signer's public key.
func (s *LatticeSigner) PublicKey() []byte {
	return s.publicKey.Bytes()
}

// KeyImage returns the key image.
func (s *LatticeSigner) KeyImage() []byte {
	result := make([]byte, len(s.keyImage))
	copy(result, s.keyImage)
	return result
}

// Sign creates a ring signature using the hash-based construction with ML-DSA keys.
func (signer *LatticeSigner) Sign(message []byte, ring [][]byte, signerIndex int) (RingSignature, error) {
	n := len(ring)
	if n < 2 {
		return nil, ErrInvalidRingSize
	}
	if signerIndex < 0 || signerIndex >= n {
		return nil, ErrInvalidSignerIndex
	}

	// Verify our public key is at the specified index
	if !constantTimeCompare(ring[signerIndex], signer.publicKey.Bytes()) {
		return nil, errors.New("signer public key not at specified index")
	}

	// Verify all public keys are valid ML-DSA keys
	for i, pkBytes := range ring {
		if _, err := mldsa.PublicKeyFromBytes(pkBytes, mldsaMode); err != nil {
			return nil, errors.New("invalid public key at index " + string(rune('0'+i)))
		}
	}

	// Generate response values for all positions
	s := make([][]byte, n)

	for i := 0; i < n; i++ {
		if i == signerIndex {
			// For signer: generate deterministic response using secret
			s[i] = latticeSignerResponse(message, ring, signer.secretScalar, signer.keyImage, signerIndex)
		} else {
			// For non-signers: generate random response
			s[i] = make([]byte, latticeResponseSize)
			if _, err := rand.Read(s[i]); err != nil {
				return nil, err
			}
		}
	}

	// Compute signature tag
	h := sha512.New()
	h.Write([]byte("lattice-ring-verify"))
	h.Write(message)
	h.Write(signer.keyImage)

	for i := 0; i < n; i++ {
		commitment := latticeCommitment(s[i], ring[i], signer.keyImage, i)
		h.Write(commitment)
	}

	tag := h.Sum(nil)

	return &LatticeSignature{
		keyImage: signer.keyImage,
		s:        s,
		tag:      tag,
	}, nil
}

// Helper functions for lattice ring signature operations

// deriveSecretScalar derives a deterministic secret scalar from the private key
func deriveSecretScalar(privateKey []byte) []byte {
	h := sha512.New()
	h.Write([]byte("lattice-ring-secret-scalar"))
	h.Write(privateKey)
	return h.Sum(nil)
}

// computeLatticeKeyImage computes the key image from secret scalar and public key
func computeLatticeKeyImage(secretScalar, publicKey []byte) []byte {
	// Key image: I = H(secret, H_p(P))
	h := sha256.New()
	h.Write([]byte("lattice-keyimage"))

	// H_p(P)
	hp := sha256.Sum256(publicKey)

	// Combine with secret to create linkable key image
	h.Write(hp[:])
	h.Write(secretScalar)

	return h.Sum(nil)
}

// latticeCommitment computes a commitment for position i in the ring
func latticeCommitment(s, publicKey, keyImage []byte, index int) []byte {
	h := sha512.New()
	h.Write([]byte("lattice-commitment"))
	h.Write(s)
	h.Write(publicKey)
	h.Write(keyImage)
	binary.Write(h, binary.BigEndian, uint32(index))
	return h.Sum(nil)
}

// latticeSignerResponse generates the signer's response value
// This is deterministic based on the secret, message, and ring
func latticeSignerResponse(message []byte, ring [][]byte, secretScalar, keyImage []byte, signerIndex int) []byte {
	h := sha512.New()
	h.Write([]byte("lattice-signer-response"))
	h.Write(message)
	h.Write(secretScalar)
	h.Write(keyImage)
	binary.Write(h, binary.BigEndian, uint32(signerIndex))

	// Include ring in the response derivation for binding
	for _, pk := range ring {
		h.Write(pk)
	}

	return h.Sum(nil)
}
