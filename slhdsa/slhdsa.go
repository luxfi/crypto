// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package slhdsa implements SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
// using Cloudflare's circl library with automatic CGO optimizations when available.
//
// SLH-DSA (FIPS 205, formerly SPHINCS+) is a post-quantum signature scheme based on
// hash functions. It provides quantum-resistant digital signatures with stateless operation.
package slhdsa

import (
	"crypto"
	"errors"
	"io"
	"runtime"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Mode represents different security levels and variants of SLH-DSA
type Mode int

const (
	// SHA2_128s provides 128-bit security with small signatures (NIST Level 1)
	SHA2_128s Mode = iota
	// SHAKE_128s provides 128-bit security with small signatures using SHAKE (NIST Level 1)
	SHAKE_128s
	// SHA2_128f provides 128-bit security with fast signing (NIST Level 1)
	SHA2_128f
	// SHAKE_128f provides 128-bit security with fast signing using SHAKE (NIST Level 1)
	SHAKE_128f

	// SHA2_192s provides 192-bit security with small signatures (NIST Level 3)
	SHA2_192s
	// SHAKE_192s provides 192-bit security with small signatures using SHAKE (NIST Level 3)
	SHAKE_192s
	// SHA2_192f provides 192-bit security with fast signing (NIST Level 3)
	SHA2_192f
	// SHAKE_192f provides 192-bit security with fast signing using SHAKE (NIST Level 3)
	SHAKE_192f

	// SHA2_256s provides 256-bit security with small signatures (NIST Level 5)
	SHA2_256s
	// SHAKE_256s provides 256-bit security with small signatures using SHAKE (NIST Level 5)
	SHAKE_256s
	// SHA2_256f provides 256-bit security with fast signing (NIST Level 5)
	SHA2_256f
	// SHAKE_256f provides 256-bit security with fast signing using SHAKE (NIST Level 5)
	SHAKE_256f
)

var (
	ErrInvalidMode      = errors.New("invalid SLH-DSA mode")
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidSignature = errors.New("invalid signature")
)

// PrivateKey represents an SLH-DSA private key
type PrivateKey struct {
	mode      Mode
	secretKey []byte
	PublicKey *PublicKey
}

// PublicKey represents an SLH-DSA public key
type PublicKey struct {
	mode      Mode
	publicKey []byte
}

// modeToID converts our Mode to circl's ID
func modeToID(mode Mode) slhdsa.ID {
	switch mode {
	case SHA2_128s:
		return slhdsa.SHA2_128s
	case SHAKE_128s:
		return slhdsa.SHAKE_128s
	case SHA2_128f:
		return slhdsa.SHA2_128f
	case SHAKE_128f:
		return slhdsa.SHAKE_128f
	case SHA2_192s:
		return slhdsa.SHA2_192s
	case SHAKE_192s:
		return slhdsa.SHAKE_192s
	case SHA2_192f:
		return slhdsa.SHA2_192f
	case SHAKE_192f:
		return slhdsa.SHAKE_192f
	case SHA2_256s:
		return slhdsa.SHA2_256s
	case SHAKE_256s:
		return slhdsa.SHAKE_256s
	case SHA2_256f:
		return slhdsa.SHA2_256f
	case SHAKE_256f:
		return slhdsa.SHAKE_256f
	default:
		return 0 // invalid
	}
}

// GetPublicKeySize returns the size of a public key for the given mode
func GetPublicKeySize(mode Mode) int {
	id := modeToID(mode)
	if !id.IsValid() {
		return 0
	}
	params := id.String()
	// Public key is 2*n where n depends on security level:
	// 128-bit: n=16 -> 32 bytes
	// 192-bit: n=24 -> 48 bytes
	// 256-bit: n=32 -> 64 bytes
	switch mode {
	case SHA2_128s, SHAKE_128s, SHA2_128f, SHAKE_128f:
		return 32
	case SHA2_192s, SHAKE_192s, SHA2_192f, SHAKE_192f:
		return 48
	case SHA2_256s, SHAKE_256s, SHA2_256f, SHAKE_256f:
		return 64
	default:
		_ = params // avoid unused variable
		return 0
	}
}

// GetSignatureSize returns the size of a signature for the given mode
func GetSignatureSize(mode Mode) int {
	id := modeToID(mode)
	if !id.IsValid() {
		return 0
	}
	// Signature sizes vary by mode (small vs fast)
	// These are from FIPS 205 specification
	switch mode {
	case SHA2_128s, SHAKE_128s:
		return 7856 // 128-bit small
	case SHA2_128f, SHAKE_128f:
		return 17088 // 128-bit fast
	case SHA2_192s, SHAKE_192s:
		return 16224 // 192-bit small
	case SHA2_192f, SHAKE_192f:
		return 35664 // 192-bit fast
	case SHA2_256s, SHAKE_256s:
		return 29792 // 256-bit small
	case SHA2_256f, SHAKE_256f:
		return 49856 // 256-bit fast
	default:
		return 0
	}
}

// GetPrivateKeySize returns the size of a private key for the given mode.
// FIPS 205 §10 catalogue: sk = 4n where n is the hash output width:
//
//	128-bit security : n=16 -> sk=64
//	192-bit security : n=24 -> sk=96
//	256-bit security : n=32 -> sk=128
func GetPrivateKeySize(mode Mode) int {
	switch mode {
	case SHA2_128s, SHAKE_128s, SHA2_128f, SHAKE_128f:
		return 64
	case SHA2_192s, SHAKE_192s, SHA2_192f, SHAKE_192f:
		return 96
	case SHA2_256s, SHAKE_256s, SHA2_256f, SHAKE_256f:
		return 128
	default:
		return 0
	}
}

// GenerateKey generates a new SLH-DSA key pair using circl
func GenerateKey(rand io.Reader, mode Mode) (*PrivateKey, error) {
	id := modeToID(mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	pub, priv, err := slhdsa.GenerateKey(rand, id)
	if err != nil {
		return nil, err
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pk := &PrivateKey{
		mode:      mode,
		secretKey: privBytes,
		PublicKey: &PublicKey{
			mode:      mode,
			publicKey: pubBytes,
		},
	}
	runtime.SetFinalizer(pk, (*PrivateKey).Zeroize)
	return pk, nil
}

// Sign signs a message with the private key using circl.
// Uses nil context -- callers requiring domain separation should use SignCtx.
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignCtx(rand, message, nil)
}

// SignCtx signs a message with domain-separating context.
// FIPS 205: ctx is an optional octet string bound into the signature.
// Callers SHOULD use a non-nil context to prevent cross-protocol signature replay.
func (priv *PrivateKey) SignCtx(rand io.Reader, message, ctx []byte) ([]byte, error) {
	id := modeToID(priv.mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	var sk slhdsa.PrivateKey
	sk.ID = id
	if err := (&sk).UnmarshalBinary(priv.secretKey); err != nil {
		return nil, err
	}

	msg := slhdsa.NewMessage(message)
	signature, err := slhdsa.SignDeterministic(&sk, msg, ctx)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify verifies a signature with the public key using circl
// The opts parameter is ignored but kept for crypto.Signer interface compatibility
func (pub *PublicKey) Verify(message, signature []byte, opts crypto.SignerOpts) bool {
	return pub.VerifySignature(message, signature)
}

// VerifySignature verifies a signature with the public key (simplified API).
// Uses nil context -- callers requiring domain separation should use VerifySignatureCtx.
func (pub *PublicKey) VerifySignature(message, signature []byte) bool {
	return pub.VerifySignatureCtx(message, signature, nil)
}

// VerifySignatureCtx verifies a signature with domain-separating context.
// FIPS 205: ctx is an optional octet string bound into the signature.
// Callers SHOULD use a non-nil context to prevent cross-protocol signature replay.
func (pub *PublicKey) VerifySignatureCtx(message, signature, ctx []byte) bool {
	id := modeToID(pub.mode)
	if !id.IsValid() {
		return false
	}

	var pk slhdsa.PublicKey
	pk.ID = id
	if err := (&pk).UnmarshalBinary(pub.publicKey); err != nil {
		return false
	}

	msg := slhdsa.NewMessage(message)
	return slhdsa.Verify(&pk, msg, signature, ctx)
}

// Public returns the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.PublicKey
}

// Bytes returns the serialized private key
func (priv *PrivateKey) Bytes() []byte {
	return priv.secretKey
}

// Zeroize overwrites the private key material with zeros.
// Best-effort: the Go runtime may have copied the bytes elsewhere.
// A GC finalizer calls this automatically when the key becomes unreachable,
// but callers should call it explicitly when the key is no longer needed
// for more predictable cleanup.
func (priv *PrivateKey) Zeroize() {
	for i := range priv.secretKey {
		priv.secretKey[i] = 0
	}
}

// Bytes returns the serialized public key
func (pub *PublicKey) Bytes() []byte {
	return pub.publicKey
}

// PrivateKeyFromBytes deserializes a private key
func PrivateKeyFromBytes(mode Mode, data []byte) (*PrivateKey, error) {
	id := modeToID(mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	// Validate size
	var sk slhdsa.PrivateKey
	sk.ID = id
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, ErrInvalidKeySize
	}

	// Extract public key
	pub := sk.PublicKey()
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	priv := &PrivateKey{
		mode:      mode,
		secretKey: data,
		PublicKey: &PublicKey{
			mode:      mode,
			publicKey: pubBytes,
		},
	}
	runtime.SetFinalizer(priv, (*PrivateKey).Zeroize)
	return priv, nil
}

// PublicKeyFromBytes deserializes a public key
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	expectedSize := GetPublicKeySize(mode)
	if expectedSize == 0 {
		return nil, ErrInvalidMode
	}
	if len(data) != expectedSize {
		return nil, ErrInvalidKeySize
	}

	id := modeToID(mode)
	if !id.IsValid() {
		return nil, ErrInvalidMode
	}

	// Validate by trying to unmarshal
	var pk slhdsa.PublicKey
	pk.ID = id
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &PublicKey{
		mode:      mode,
		publicKey: data,
	}, nil
}
