//go:build cgo
// +build cgo

package mldsa

import (
	"crypto"
	"io"
)

// UseCGO returns whether CGO optimizations are available
func UseCGO() bool {
	return true
}

// GenerateKeyCGO generates a key pair using CGO optimizations
func GenerateKeyCGO(rand io.Reader, mode Mode) (*PrivateKey, error) {
	// TODO: Implement actual CGO version with optimized C code
	return GenerateKey(rand, mode)
}

// SignCGO signs using CGO optimizations
func SignCGO(priv *PrivateKey, rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	// TODO: Implement actual CGO version with optimized C code
	return priv.Sign(rand, message, opts)
}

// VerifyCGO verifies using CGO optimizations
func VerifyCGO(pub *PublicKey, message, signature []byte) bool {
	// TODO: Implement actual CGO version with optimized C code
	return pub.Verify(message, signature)
}
