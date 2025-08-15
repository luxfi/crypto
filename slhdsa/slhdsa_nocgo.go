//go:build !cgo
// +build !cgo

package slhdsa

import (
	"crypto"
	"io"
)

// UseCGO returns whether CGO optimizations are available
func UseCGO() bool {
	return false
}

// GenerateKeyCGO generates a key pair (falls back to pure Go)
func GenerateKeyCGO(rand io.Reader, mode Mode) (*PrivateKey, error) {
	return GenerateKey(rand, mode)
}

// SignCGO signs (falls back to pure Go)
func SignCGO(priv *PrivateKey, rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.Sign(rand, message, opts)
}

// VerifyCGO verifies (falls back to pure Go)
func VerifyCGO(pub *PublicKey, message, signature []byte) bool {
	return pub.Verify(message, signature)
}
