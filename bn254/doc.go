// Package bn254 is the canonical entry point for the BN254 (alt_bn128)
// pairing-friendly elliptic curve used by EVM precompiles.
//
// BN254 and BN256 are the same curve under different names. This package
// re-exports github.com/luxfi/crypto/bn256 so consumers can spell the
// name either way and get identical types.
package bn254

import "github.com/luxfi/crypto/bn256"

// G1 is a point on the BN254 G1 group.
type G1 = bn256.G1

// G2 is a point on the BN254 G2 group.
type G2 = bn256.G2

// PairingCheck computes the multi-pairing check used by the EVM precompile.
func PairingCheck(a []*G1, b []*G2) bool { return bn256.PairingCheck(a, b) }
