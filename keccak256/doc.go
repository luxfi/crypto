// Package keccak implements the Keccak-256 hash function used by Ethereum.
//
// This is the canonical entry point for Keccak-256 in the luxfi/crypto module.
// It dispatches between three implementations:
//
//   - vanilla: golang.org/x/crypto/sha3.NewLegacyKeccak256 (pure Go)
//   - cgo:     uses libluxcrypto's optimised C implementation when CGO is on
//   - gpu:     batch-routes through github.com/luxfi/accel for batches that
//     exceed the BatchThreshold cutoff
//
// The dispatcher honours backend.Default(); see github.com/luxfi/crypto/backend.
package keccak256
