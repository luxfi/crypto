// Package ed25519 is the canonical entry point for Ed25519 signatures
// in luxfi/crypto.
//
// It is a thin wrapper over crypto/ed25519 in the standard library, with a
// batch verifier that can dispatch to GPU through github.com/luxfi/accel.
package ed25519
