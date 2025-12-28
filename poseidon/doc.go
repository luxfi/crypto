// Package poseidon is the canonical entry point for Poseidon-flavoured
// hash functions in luxfi/crypto.
//
// Two variants are exposed:
//
//   - Sum: classical Poseidon (Grassi-Khovratovich-Lüftenegger-Rechberger-
//     Roy-Schofnegger 2021) used by zkSNARK toolchains.
//   - Sum2: Poseidon2 (Grassi-Khovratovich-Roy 2023) — preferred for new
//     code as it offers a 2-3x speedup on Cortex/x86 with the same
//     security level.
//
// The classical Poseidon entry uses the gnark-crypto BN254 implementation
// for compatibility with the Verkle and Plonky2 ecosystems. The Poseidon2
// entry routes through luxfi/crypto/hash/poseidon2 which has GPU
// acceleration on platforms that ship the luxcpp Metal kernel.
package poseidon
