// Package promptseal is the confidentiality envelope for Proof-of-Inference: it seals a user's
// prompt to an operator's registered public key so the prompt is NEVER plaintext on the wire and
// only the chosen operator — inside its compute boundary — can open it. This closes the audit's G9:
// the default inference path handed the operator the plaintext prompt by hash; now the operator
// registry carries a recipient KEM key and the requester seals to it.
//
// It is a thin, single-shot wrapper over RFC 9180 HPKE (base mode) with X25519 + HKDF-SHA256 +
// ChaCha20-Poly1305 — the same primitive the rest of the stack uses (github.com/cloudflare/circl).
// The associated data (aad) binds the ciphertext to its context (e.g. the intentID), so a sealed
// prompt cannot be replayed under a different request.
package promptseal

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/hpke"
)

// Info domain-separates this use of HPKE from any other in the stack.
var info = []byte("hanzo/poi/prompt-seal/v1")

// suite: X25519-HKDF-SHA256 KEM, HKDF-SHA256 KDF, ChaCha20-Poly1305 AEAD.
var suite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)

// kemScheme is the X25519 KEM; its encapsulated key ("enc") is 32 bytes.
var kemScheme = hpke.KEM_X25519_HKDF_SHA256.Scheme()

// encLen is the X25519 encapsulated-key length prefixed to every sealed blob.
var encLen = kemScheme.EncapsulationSeedSize() // 32 for X25519

var (
	ErrShortSealed = errors.New("promptseal: sealed blob shorter than the encapsulated key")
	ErrBadKey      = errors.New("promptseal: malformed operator key")
)

// GenerateOperatorKey returns an operator's (publicKey, privateKey) for its registry entry. The
// public key is published on-chain; the private key never leaves the operator's compute boundary.
func GenerateOperatorKey() (pub, priv []byte, err error) {
	pk, sk, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pub, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	priv, err = sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// SealPrompt seals `prompt` to an operator's `operatorPub`, binding `aad` (context, e.g. intentID).
// Output is `enc ‖ ciphertext`. Semantically secure: two seals of the same prompt differ, and the
// blob reveals nothing about the prompt to anyone without the operator's private key.
func SealPrompt(operatorPub, prompt, aad []byte) ([]byte, error) {
	pk, err := kemScheme.UnmarshalBinaryPublicKey(operatorPub)
	if err != nil {
		return nil, ErrBadKey
	}
	sender, err := suite.NewSender(pk, info)
	if err != nil {
		return nil, err
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(prompt, aad)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), enc...), ct...), nil
}

// OpenPrompt opens a sealed blob with the operator's `operatorPriv` and the same `aad`. Returns an
// error if the key is wrong, the blob was tampered, or the aad does not match (AEAD authentication).
func OpenPrompt(operatorPriv, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < encLen {
		return nil, ErrShortSealed
	}
	sk, err := kemScheme.UnmarshalBinaryPrivateKey(operatorPriv)
	if err != nil {
		return nil, ErrBadKey
	}
	receiver, err := suite.NewReceiver(sk, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(sealed[:encLen])
	if err != nil {
		return nil, err
	}
	return opener.Open(sealed[encLen:], aad)
}
