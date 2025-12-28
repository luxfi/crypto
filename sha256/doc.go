// Package sha256 is the canonical entry point for SHA-256 in luxfi/crypto.
//
// It is a thin wrapper over crypto/sha256 in the standard library, with an
// optional batch entry that can dispatch to GPU through github.com/luxfi/accel.
package sha256
