// Package pedersen is the canonical entry point for Pedersen commitments
// over the BN254 scalar field.
//
// A Pedersen commitment Commit(m, r) = m*G + r*H where G and H are
// independently sampled, prover-public generators of an elliptic curve
// group. The commitment is hiding (under the discrete-log assumption for
// H) and binding.
//
// This package wraps gnark-crypto BN254 G1 arithmetic. For Verkle-tree
// commitments use luxfi/crypto/ipa instead.
package pedersen
