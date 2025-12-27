// Package gpu provides GPU-accelerated cryptographic operations.
package gpu

// Sizes
// Note: gnark-crypto uses uncompressed point serialization:
// - G1 (public key): 96 bytes uncompressed
// - G2 (signature): 192 bytes uncompressed
const (
	BLSSecretKeySize = 32
	BLSPublicKeySize = 96  // G1 uncompressed
	BLSSignatureSize = 192 // G2 uncompressed
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
