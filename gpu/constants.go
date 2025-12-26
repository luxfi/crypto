// Package gpu provides GPU-accelerated cryptographic operations.
package gpu

// Sizes
const (
	BLSSecretKeySize = 32
	BLSPublicKeySize = 48
	BLSSignatureSize = 96
	BLSMessageSize   = 32

	MLDSASecretKeySize = 4032
	MLDSAPublicKeySize = 1952
	MLDSASignatureSize = 3309
)

// Hash types for batch hashing
const (
	HashTypeSHA3_256 = 0
	HashTypeSHA3_512 = 1
	HashTypeBLAKE3   = 2
)
