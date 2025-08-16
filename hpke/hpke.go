// Package hpke provides Hybrid Public Key Encryption (RFC 9180) implementation
// based on Cloudflare CIRCL library
package hpke

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
)

// Suite represents an HPKE cipher suite
type Suite = hpke.Suite

// Available HPKE suites
var (
	// X25519 with HKDF-SHA256 and AES-128-GCM
	DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM = hpke.DHKEM_X25519_HKDF_SHA256.Suite(
		hpke.HKDF_SHA256,
		hpke.AES_128_GCM,
	)
	
	// X25519 with HKDF-SHA256 and ChaCha20Poly1305
	DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305 = hpke.DHKEM_X25519_HKDF_SHA256.Suite(
		hpke.HKDF_SHA256,
		hpke.ChaCha20Poly1305,
	)
	
	// P256 with HKDF-SHA256 and AES-128-GCM
	DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM = hpke.DHKEM_P256_HKDF_SHA256.Suite(
		hpke.HKDF_SHA256,
		hpke.AES_128_GCM,
	)
	
	// P384 with HKDF-SHA384 and AES-256-GCM
	DHKEM_P384_HKDF_SHA384__HKDF_SHA384__AES_256_GCM = hpke.DHKEM_P384_HKDF_SHA384.Suite(
		hpke.HKDF_SHA384,
		hpke.AES_256_GCM,
	)
	
	// P521 with HKDF-SHA512 and AES-256-GCM
	DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM = hpke.DHKEM_P521_HKDF_SHA512.Suite(
		hpke.HKDF_SHA512,
		hpke.AES_256_GCM,
	)
	
	// X448 with HKDF-SHA512 and AES-256-GCM
	DHKEM_X448_HKDF_SHA512__HKDF_SHA512__AES_256_GCM = hpke.DHKEM_X448_HKDF_SHA512.Suite(
		hpke.HKDF_SHA512,
		hpke.AES_256_GCM,
	)
)

// Mode represents the HPKE mode
type Mode uint8

const (
	// ModeBase is the base mode (no sender authentication)
	ModeBase Mode = iota
	// ModePSK uses a pre-shared key
	ModePSK
	// ModeAuth includes sender authentication
	ModeAuth
	// ModeAuthPSK combines authentication and PSK
	ModeAuthPSK
)

// Context represents an HPKE encryption/decryption context
type Context struct {
	suite   Suite
	mode    Mode
	context interface{} // Either sender or receiver context
}

// PrivateKey represents an HPKE private key
type PrivateKey struct {
	suite Suite
	key   hpke.PrivateKey
}

// PublicKey represents an HPKE public key
type PublicKey struct {
	suite Suite
	key   hpke.PublicKey
}

// EncapsulatedKey represents the encapsulated key sent with ciphertext
type EncapsulatedKey []byte

// GenerateKeyPair generates a new HPKE key pair
func GenerateKeyPair(suite Suite) (*PrivateKey, *PublicKey, error) {
	kem := suite.KEM()
	scheme := kem.Scheme()
	
	seed := make([]byte, scheme.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	
	privateKey, publicKey, err := scheme.DeriveKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key pair: %w", err)
	}
	
	return &PrivateKey{
			suite: suite,
			key:   privateKey,
		}, &PublicKey{
			suite: suite,
			key:   publicKey,
		}, nil
}

// DeriveKeyPair derives an HPKE key pair from a seed
func DeriveKeyPair(suite Suite, seed []byte) (*PrivateKey, *PublicKey, error) {
	kem := suite.KEM()
	scheme := kem.Scheme()
	
	if len(seed) != scheme.SeedSize() {
		return nil, nil, fmt.Errorf("invalid seed size: got %d, want %d", len(seed), scheme.SeedSize())
	}
	
	privateKey, publicKey, err := scheme.DeriveKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key pair: %w", err)
	}
	
	return &PrivateKey{
			suite: suite,
			key:   privateKey,
		}, &PublicKey{
			suite: suite,
			key:   publicKey,
		}, nil
}

// Public returns the public key corresponding to the private key
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		suite: k.suite,
		key:   k.key.Public(),
	}
}

// Bytes returns the private key as bytes
func (k *PrivateKey) Bytes() []byte {
	data, _ := k.key.MarshalBinary()
	return data
}

// PrivateKeyFromBytes creates a private key from bytes
func PrivateKeyFromBytes(suite Suite, data []byte) (*PrivateKey, error) {
	kem := suite.KEM()
	scheme := kem.Scheme()
	
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	
	return &PrivateKey{
		suite: suite,
		key:   privateKey,
	}, nil
}

// Bytes returns the public key as bytes
func (k *PublicKey) Bytes() []byte {
	data, _ := k.key.MarshalBinary()
	return data
}

// PublicKeyFromBytes creates a public key from bytes
func PublicKeyFromBytes(suite Suite, data []byte) (*PublicKey, error) {
	kem := suite.KEM()
	scheme := kem.Scheme()
	
	publicKey, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	
	return &PublicKey{
		suite: suite,
		key:   publicKey,
	}, nil
}

// SetupBaseS creates a sender context for base mode
func SetupBaseS(suite Suite, recipientPublicKey *PublicKey, info []byte) (*Context, EncapsulatedKey, error) {
	if recipientPublicKey == nil {
		return nil, nil, errors.New("recipient public key is required")
	}
	if recipientPublicKey.suite != suite {
		return nil, nil, errors.New("public key suite mismatch")
	}
	
	sender, err := suite.NewSender(recipientPublicKey.key, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sender: %w", err)
	}
	
	enc := sender.Enc()
	
	return &Context{
		suite:   suite,
		mode:    ModeBase,
		context: sender,
	}, enc, nil
}

// SetupBaseR creates a receiver context for base mode
func SetupBaseR(suite Suite, enc EncapsulatedKey, privateKey *PrivateKey, info []byte) (*Context, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if privateKey.suite != suite {
		return nil, errors.New("private key suite mismatch")
	}
	
	receiver, err := suite.NewReceiver(privateKey.key, enc, info)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}
	
	return &Context{
		suite:   suite,
		mode:    ModeBase,
		context: receiver,
	}, nil
}

// SetupPSKS creates a sender context for PSK mode
func SetupPSKS(suite Suite, recipientPublicKey *PublicKey, psk, pskID, info []byte) (*Context, EncapsulatedKey, error) {
	if recipientPublicKey == nil {
		return nil, nil, errors.New("recipient public key is required")
	}
	if recipientPublicKey.suite != suite {
		return nil, nil, errors.New("public key suite mismatch")
	}
	if len(psk) == 0 {
		return nil, nil, errors.New("PSK is required")
	}
	
	sender, err := suite.NewSenderPSK(recipientPublicKey.key, psk, pskID, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create PSK sender: %w", err)
	}
	
	enc := sender.Enc()
	
	return &Context{
		suite:   suite,
		mode:    ModePSK,
		context: sender,
	}, enc, nil
}

// SetupPSKR creates a receiver context for PSK mode
func SetupPSKR(suite Suite, enc EncapsulatedKey, privateKey *PrivateKey, psk, pskID, info []byte) (*Context, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if privateKey.suite != suite {
		return nil, errors.New("private key suite mismatch")
	}
	if len(psk) == 0 {
		return nil, errors.New("PSK is required")
	}
	
	receiver, err := suite.NewReceiverPSK(privateKey.key, enc, psk, pskID, info)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSK receiver: %w", err)
	}
	
	return &Context{
		suite:   suite,
		mode:    ModePSK,
		context: receiver,
	}, nil
}

// SetupAuthS creates a sender context for authenticated mode
func SetupAuthS(suite Suite, recipientPublicKey *PublicKey, senderPrivateKey *PrivateKey, info []byte) (*Context, EncapsulatedKey, error) {
	if recipientPublicKey == nil || senderPrivateKey == nil {
		return nil, nil, errors.New("both recipient public key and sender private key are required")
	}
	if recipientPublicKey.suite != suite || senderPrivateKey.suite != suite {
		return nil, nil, errors.New("key suite mismatch")
	}
	
	sender, err := suite.NewSenderAuth(recipientPublicKey.key, senderPrivateKey.key, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create auth sender: %w", err)
	}
	
	enc := sender.Enc()
	
	return &Context{
		suite:   suite,
		mode:    ModeAuth,
		context: sender,
	}, enc, nil
}

// SetupAuthR creates a receiver context for authenticated mode
func SetupAuthR(suite Suite, enc EncapsulatedKey, privateKey *PrivateKey, senderPublicKey *PublicKey, info []byte) (*Context, error) {
	if privateKey == nil || senderPublicKey == nil {
		return nil, errors.New("both private key and sender public key are required")
	}
	if privateKey.suite != suite || senderPublicKey.suite != suite {
		return nil, errors.New("key suite mismatch")
	}
	
	receiver, err := suite.NewReceiverAuth(privateKey.key, enc, senderPublicKey.key, info)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth receiver: %w", err)
	}
	
	return &Context{
		suite:   suite,
		mode:    ModeAuth,
		context: receiver,
	}, nil
}

// Seal encrypts a message with optional associated data
func (c *Context) Seal(plaintext, aad []byte) ([]byte, error) {
	switch ctx := c.context.(type) {
	case hpke.Sender:
		return ctx.Seal(plaintext, aad), nil
	default:
		return nil, errors.New("context is not a sender")
	}
}

// Open decrypts a ciphertext with optional associated data
func (c *Context) Open(ciphertext, aad []byte) ([]byte, error) {
	switch ctx := c.context.(type) {
	case hpke.Receiver:
		plaintext, err := ctx.Open(ciphertext, aad)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
		return plaintext, nil
	default:
		return nil, errors.New("context is not a receiver")
	}
}

// Export derives key material from the context
func (c *Context) Export(context []byte, length int) []byte {
	switch ctx := c.context.(type) {
	case hpke.Sender:
		return ctx.Export(context, length)
	case hpke.Receiver:
		return ctx.Export(context, length)
	default:
		return nil
	}
}

// Suite returns the cipher suite of the context
func (c *Context) Suite() Suite {
	return c.suite
}

// Mode returns the mode of the context
func (c *Context) Mode() Mode {
	return c.mode
}

// SingleShotEncrypt performs single-shot encryption (base mode)
func SingleShotEncrypt(suite Suite, recipientPublicKey *PublicKey, plaintext, aad, info []byte) (enc EncapsulatedKey, ciphertext []byte, err error) {
	ctx, enc, err := SetupBaseS(suite, recipientPublicKey, info)
	if err != nil {
		return nil, nil, err
	}
	
	ciphertext, err = ctx.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	
	return enc, ciphertext, nil
}

// SingleShotDecrypt performs single-shot decryption (base mode)
func SingleShotDecrypt(suite Suite, enc EncapsulatedKey, privateKey *PrivateKey, ciphertext, aad, info []byte) (plaintext []byte, err error) {
	ctx, err := SetupBaseR(suite, enc, privateKey, info)
	if err != nil {
		return nil, err
	}
	
	return ctx.Open(ciphertext, aad)
}

// RandomBytes generates random bytes using crypto/rand
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}