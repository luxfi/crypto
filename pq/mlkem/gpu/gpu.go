//go:build !cgo

// Package gpu provides ML-KEM operations with CPU fallback when CGO is disabled.
package gpu

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/luxfi/crypto/mlkem"
)

const (
	BatchEncapsThreshold = 16
	BatchDecapsThreshold = 16
)

// Available returns false when CGO is disabled.
func Available() bool { return false }

// Threshold returns the batch threshold.
func Threshold() int { return BatchEncapsThreshold }

// KeyGen generates a key pair using pure Go.
func KeyGen(mode mlkem.Mode, reader io.Reader) (*mlkem.PublicKey, *mlkem.PrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	return mlkem.GenerateKeyPair(reader, mode)
}

// BatchEncaps encapsulates shared secrets using pure Go (no GPU acceleration).
func BatchEncaps(pks []*mlkem.PublicKey, reader io.Reader) ([][]byte, [][]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	cts := make([][]byte, len(pks))
	sss := make([][]byte, len(pks))
	for i, pk := range pks {
		if pk == nil {
			return nil, nil, errors.New("nil public key")
		}
		ct, ss, err := pk.Encapsulate(reader)
		if err != nil {
			return nil, nil, err
		}
		cts[i] = ct
		sss[i] = ss
	}
	return cts, sss, nil
}

// BatchDecaps decapsulates shared secrets using pure Go (no GPU acceleration).
func BatchDecaps(sk *mlkem.PrivateKey, cts [][]byte) ([][]byte, error) {
	if sk == nil {
		return nil, errors.New("nil private key")
	}
	sss := make([][]byte, len(cts))
	for i, ct := range cts {
		ss, err := sk.Decapsulate(ct)
		if err != nil {
			return nil, err
		}
		sss[i] = ss
	}
	return sss, nil
}

// Destroy is a no-op for pure Go.
func Destroy() {}
