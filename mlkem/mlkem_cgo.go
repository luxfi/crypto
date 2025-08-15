//go:build cgo
// +build cgo

package mlkem

import "io"

// UseCGO returns whether CGO optimizations are available
func UseCGO() bool {
	return true
}

// GenerateKeyPairCGO generates a key pair using CGO optimizations
func GenerateKeyPairCGO(rand io.Reader, mode Mode) (*PrivateKey, error) {
	// TODO: Implement actual CGO version
	return GenerateKeyPair(rand, mode)
}

// EncapsulateCGO encapsulates using CGO optimizations
func EncapsulateCGO(pub *PublicKey, rand io.Reader) (*EncapsulationResult, error) {
	// TODO: Implement actual CGO version
	return pub.Encapsulate(rand)
}

// DecapsulateCGO decapsulates using CGO optimizations
func DecapsulateCGO(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	// TODO: Implement actual CGO version
	return priv.Decapsulate(ciphertext)
}
