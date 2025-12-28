// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	stded "crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
)

// Sizes are the same as the standard library; re-exported for convenience.
const (
	PublicKeySize  = stded.PublicKeySize
	PrivateKeySize = stded.PrivateKeySize
	SignatureSize  = stded.SignatureSize
	SeedSize       = stded.SeedSize
)

// BatchThreshold is the minimum batch length at which BatchVerify will try to
// route through GPU.
var BatchThreshold = 64

// PublicKey, PrivateKey, and Signature are aliases for the stdlib types so
// callers can mix this package and crypto/ed25519 freely.
type (
	PublicKey  = stded.PublicKey
	PrivateKey = stded.PrivateKey
)

// GenerateKey generates a fresh keypair using rng. If rng is nil it uses
// crypto/rand.
func GenerateKey(rng io.Reader) (PublicKey, PrivateKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	return stded.GenerateKey(rng)
}

// NewKeyFromSeed deterministically derives a private key from a 32-byte seed.
func NewKeyFromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("ed25519: seed length must be 32")
	}
	return stded.NewKeyFromSeed(seed), nil
}

// Sign produces a signature for msg.
func Sign(priv PrivateKey, msg []byte) []byte { return stded.Sign(priv, msg) }

// Verify reports whether sig is a valid signature of msg by pub.
func Verify(pub PublicKey, msg, sig []byte) bool { return stded.Verify(pub, msg, sig) }

// BatchVerify verifies a slice of (pub, msg, sig) triples. The result slice
// has one boolean per input. When the batch is large enough and a GPU
// backend is available the verification runs on the GPU; otherwise it
// runs on the CPU. Output is byte-identical to repeated calls to Verify.
func BatchVerify(pubs []PublicKey, msgs [][]byte, sigs [][]byte) []bool {
	n := len(pubs)
	if n != len(msgs) || n != len(sigs) {
		panic("ed25519.BatchVerify: pubs/msgs/sigs length mismatch")
	}
	out := make([]bool, n)
	if n == 0 {
		return out
	}
	if n >= BatchThreshold {
		if ok, err := batchGPU(pubs, msgs, sigs, out); ok && err == nil {
			return out
		}
	}
	for i := range pubs {
		out[i] = stded.Verify(pubs[i], msgs[i], sigs[i])
	}
	return out
}
