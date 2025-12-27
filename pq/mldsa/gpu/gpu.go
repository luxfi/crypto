//go:build !cgo

// Package gpu provides ML-DSA operations with CPU fallback when CGO is disabled.
package gpu

import (
	"errors"

	"github.com/luxfi/crypto/mldsa"
)

const (
	BatchSignThreshold   = 16
	BatchVerifyThreshold = 32
)

// Available returns false when CGO is disabled.
func Available() bool { return false }

// Threshold returns the batch threshold.
func Threshold() int { return BatchVerifyThreshold }

// KeyGen generates a key pair using pure Go.
func KeyGen(mode mldsa.Mode, seed []byte) (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(nil, mode)
}

// BatchSign signs messages using pure Go (no GPU acceleration).
func BatchSign(priv *mldsa.PrivateKey, messages [][]byte) ([][]byte, error) {
	if priv == nil {
		return nil, errors.New("nil private key")
	}
	sigs := make([][]byte, len(messages))
	for i, msg := range messages {
		sig, err := priv.Sign(nil, msg, nil)
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}
	return sigs, nil
}

// BatchVerify verifies signatures using pure Go (no GPU acceleration).
// Matches CGO signature: pks []*PublicKey, sigs [][]byte, msgs [][]byte
func BatchVerify(pks []*mldsa.PublicKey, sigs [][]byte, msgs [][]byte) ([]bool, error) {
	n := len(pks)
	if n == 0 || n != len(sigs) || n != len(msgs) {
		return nil, errors.New("mismatched input lengths")
	}
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		if pks[i] == nil {
			results[i] = false
			continue
		}
		results[i] = pks[i].VerifySignature(msgs[i], sigs[i])
	}
	return results, nil
}

// Destroy is a no-op for pure Go.
func Destroy() {}
