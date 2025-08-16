//go:build cgo
// +build cgo

package mlkem

// This file contains CGO-optimized implementations that are only compiled
// when CGO is explicitly enabled with CGO_ENABLED=1
//
// TODO: Implement actual CGO optimizations using C libraries for:
// - ML-KEM-512/768/1024 from NIST reference implementation
// - CRYSTALS-Kyber optimized implementations
// - AVX2/AVX512 optimizations for x86_64
// - NEON optimizations for ARM64
