// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// ML-DSA (FIPS 204) precompiled contracts for EVM
// Provides on-chain post-quantum signature verification
//
// SECURITY: Only verification is exposed as a precompile. Signing and keygen
// are deliberately excluded — private key material must never appear in EVM
// calldata (it is visible to all nodes and permanently stored on-chain).

package precompile

import (
	"errors"

	"github.com/luxfi/crypto/mldsa"
)

// ML-DSA verification precompile addresses (0x0110-0x0112)
var (
	MLDSA44VerifyAddress = HexToAddress("0x0000000000000000000000000000000000000110")
	MLDSA65VerifyAddress = HexToAddress("0x0000000000000000000000000000000000000111")
	MLDSA87VerifyAddress = HexToAddress("0x0000000000000000000000000000000000000112")
)

// Gas costs for ML-DSA verification
const (
	mldsa44VerifyGas = 120000
	mldsa65VerifyGas = 180000
	mldsa87VerifyGas = 250000
)

// mldsaVerify implements ML-DSA signature verification for a given mode.
type mldsaVerify struct {
	mode mldsa.Mode
	gas  uint64
}

func (v *mldsaVerify) RequiredGas(input []byte) uint64 { return v.gas }

func (v *mldsaVerify) Run(input []byte) ([]byte, error) {
	// Input: [public_key][signature][message]
	pubKeySize := mldsa.GetPublicKeySize(v.mode)
	sigSize := mldsa.GetSignatureSize(v.mode)

	if len(input) < pubKeySize+sigSize+1 {
		return nil, errors.New("input too short")
	}

	pubKeyBytes := input[:pubKeySize]
	sigBytes := input[pubKeySize : pubKeySize+sigSize]
	message := input[pubKeySize+sigSize:]

	pubKey, err := mldsa.PublicKeyFromBytes(pubKeyBytes, v.mode)
	if err != nil {
		return nil, err
	}

	valid := pubKey.VerifySignature(message, sigBytes)

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}
	return result, nil
}

// RegisterMLDSA registers ML-DSA verification precompiles.
func RegisterMLDSA(registry *Registry) {
	registry.Register(MLDSA44VerifyAddress, &mldsaVerify{mode: mldsa.MLDSA44, gas: mldsa44VerifyGas})
	registry.Register(MLDSA65VerifyAddress, &mldsaVerify{mode: mldsa.MLDSA65, gas: mldsa65VerifyGas})
	registry.Register(MLDSA87VerifyAddress, &mldsaVerify{mode: mldsa.MLDSA87, gas: mldsa87VerifyGas})
}

func init() {
	RegisterMLDSA(PostQuantumRegistry)
}
