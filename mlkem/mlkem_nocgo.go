//go:build !cgo
// +build !cgo

package mlkem

import "io"

// UseCGO returns whether CGO optimizations are available
func UseCGO() bool {
	return false
}

// GenerateKeyPairCGO generates a key pair (falls back to pure Go)
func GenerateKeyPairCGO(rand io.Reader, mode Mode) (*PrivateKey, error) {
	return GenerateKeyPair(rand, mode)
}

// EncapsulateCGO encapsulates (falls back to pure Go)
func EncapsulateCGO(pub *PublicKey, rand io.Reader) (*EncapsulationResult, error) {
	return pub.Encapsulate(rand)
}

// DecapsulateCGO decapsulates (falls back to pure Go)
func DecapsulateCGO(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return priv.Decapsulate(ciphertext)
}
