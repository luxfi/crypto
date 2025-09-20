//go:build cgo
// +build cgo

package slhdsa

// This file contains CGO-optimized implementations that are only compiled
// when CGO is explicitly enabled with CGO_ENABLED=1
//
// CGO optimizations placeholder - currently using pure Go implementation.
// Future optimizations could include:
// - SLH-DSA-SHA2-128s/f, 192s/f, 256s/f from NIST reference implementation
// - SPHINCS+ optimized implementations
// - AVX2/AVX512 optimizations for hash functions
// - NEON optimizations for ARM64
// - Parallel tree traversal optimizations
//
// The pure Go implementation provides:
// - Full SLH-DSA compliance with FIPS 205
// - Stateless hash-based signatures
// - Cross-platform compatibility
