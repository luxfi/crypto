// Package ntt is the canonical entry point for the Number-Theoretic Transform
// used by lattice-based cryptography (ML-KEM, ML-DSA, corona).
//
// The CPU implementation here uses gnark-crypto field arithmetic. The GPU
// path routes through github.com/luxfi/accel which exposes a polynomial
// NTT kernel for prime moduli (Kyber/Dilithium-style q = 3329 / 8380417).
package ntt
