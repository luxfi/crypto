// Package blake3 implements the BLAKE3 cryptographic hash function.
//
// This is the canonical entry point for BLAKE3 in the luxfi/crypto module.
// It exposes:
//
//   - Hash:     single-input fixed-size (32 byte) digest, allocations-1.
//   - HashBatch: batch variant with optional GPU dispatch above BatchThreshold.
//   - New:      streaming hash.Hash for incremental input.
//   - NewKeyed: keyed hash (32-byte key) for MAC use.
//   - DeriveKey: KDF mode (RFC 9106-style context separation).
//   - Reader:   variable-length output stream (XOF).
//
// Backed by github.com/zeebo/blake3 (BSD-3, pure Go with SSE4.1/AVX2/NEON).
// Mirrors the lux/crypto/keccak and lux/crypto/sha256 dispatch pattern.
package blake3
