//go:build cgo
// +build cgo

package mldsa

// This file contains CGO-optimized implementations that are only compiled
// when CGO is explicitly enabled with CGO_ENABLED=1
//
// TODO: Implement actual CGO optimizations using C libraries for:
// - ML-DSA-44/65/87 from NIST reference implementation
// - CRYSTALS-Dilithium optimized implementations  
// - AVX2/AVX512 optimizations for x86_64
// - NEON optimizations for ARM64
// - Batch verification optimizations