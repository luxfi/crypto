// Package evm256 is the canonical entry point for the BN254-based EVM
// precompiles (EIP-196 / EIP-197): bn256Add, bn256ScalarMul, bn256Pairing.
//
// It re-exports github.com/luxfi/crypto/bn256 plus a small set of wrappers
// matching the EVM precompile signatures (input/output as flat byte
// slices). luxcpp/crypto/evm256/ exposes the same ABI on the C side; the
// two are kept name-equivalent for diff'ability.
package evm256
