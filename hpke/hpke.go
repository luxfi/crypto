// Package hpke provides a thin wrapper around Cloudflare's HPKE implementation
package hpke

import (
	"github.com/cloudflare/circl/hpke"
)

// Re-export the main types and constants from the circl/hpke package

// Suite represents an HPKE cipher suite
type Suite = hpke.Suite

// KEM represents a Key Encapsulation Mechanism
type KEM = hpke.KEM

// KDF represents a Key Derivation Function
type KDF = hpke.KDF

// AEAD represents an Authenticated Encryption with Associated Data algorithm
type AEAD = hpke.AEAD

// Available KEMs
const (
	KEM_P256_HKDF_SHA256   = hpke.KEM_P256_HKDF_SHA256
	KEM_P384_HKDF_SHA384   = hpke.KEM_P384_HKDF_SHA384
	KEM_P521_HKDF_SHA512   = hpke.KEM_P521_HKDF_SHA512
	KEM_X25519_HKDF_SHA256 = hpke.KEM_X25519_HKDF_SHA256
)

// Available KDFs
const (
	KDF_HKDF_SHA256 = hpke.KDF_HKDF_SHA256
	KDF_HKDF_SHA384 = hpke.KDF_HKDF_SHA384
	KDF_HKDF_SHA512 = hpke.KDF_HKDF_SHA512
)

// Available AEADs
const (
	AEAD_AES128GCM        = hpke.AEAD_AES128GCM
	AEAD_AES256GCM        = hpke.AEAD_AES256GCM
	AEAD_ChaCha20Poly1305 = hpke.AEAD_ChaCha20Poly1305
)

// NewSuite creates a new HPKE suite from components
var NewSuite = hpke.NewSuite

// Sender represents an HPKE sender context
type Sender = hpke.Sender

// Receiver represents an HPKE receiver context
type Receiver = hpke.Receiver