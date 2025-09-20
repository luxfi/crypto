//go:build cgo
// +build cgo

package mldsa

// This file contains CGO-optimized implementations that are only compiled
// when CGO is explicitly enabled with CGO_ENABLED=1
//
// CGO optimizations placeholder - currently using pure Go implementation.
// Future optimizations could include:
// - ML-DSA-44/65/87 from NIST reference implementation
// - CRYSTALS-Dilithium optimized implementations
// - AVX2/AVX512 optimizations for x86_64
// - NEON optimizations for ARM64
// - Batch verification optimizations
//
// The pure Go implementation provides:
// - Full ML-DSA compliance with FIPS 204
// - Deterministic signatures
// - Cross-platform compatibility
