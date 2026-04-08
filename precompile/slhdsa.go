// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// SLH-DSA (FIPS 205) precompiled contracts for EVM
// Provides on-chain post-quantum stateless hash-based signature verification
//
// SECURITY: Only verification is exposed as a precompile. Signing is
// deliberately excluded — private key material must never appear in EVM
// calldata (it is visible to all nodes and permanently stored on-chain).

package precompile

import (
	"errors"

	"github.com/luxfi/crypto/slhdsa"
)

// SLH-DSA verification precompile addresses (0x0130-0x0135)
var (
	SLHDSA128sVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000130")
	SLHDSA128fVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000131")
	SLHDSA192sVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000132")
	SLHDSA192fVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000133")
	SLHDSA256sVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000134")
	SLHDSA256fVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000135")
)

// Gas costs for SLH-DSA verification
const (
	slhdsa128sVerifyGas = 300000
	slhdsa128fVerifyGas = 200000
	slhdsa192sVerifyGas = 400000
	slhdsa192fVerifyGas = 300000
	slhdsa256sVerifyGas = 500000
	slhdsa256fVerifyGas = 400000
)

// slhdsaVerify implements SLH-DSA signature verification for a given mode.
type slhdsaVerify struct {
	mode slhdsa.Mode
	gas  uint64
}

func (v *slhdsaVerify) RequiredGas(input []byte) uint64 { return v.gas }

func (v *slhdsaVerify) Run(input []byte) ([]byte, error) {
	// Input: [public_key][signature][message]
	pubKeySize := slhdsa.GetPublicKeySize(v.mode)
	sigSize := slhdsa.GetSignatureSize(v.mode)

	if len(input) < pubKeySize+sigSize+1 {
		return nil, errors.New("input too short")
	}

	pubKeyBytes := input[:pubKeySize]
	sigBytes := input[pubKeySize : pubKeySize+sigSize]
	message := input[pubKeySize+sigSize:]

	pubKey, err := slhdsa.PublicKeyFromBytes(pubKeyBytes, v.mode)
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

// RegisterSLHDSA registers SLH-DSA verification precompiles.
func RegisterSLHDSA(registry *Registry) {
	registry.Register(SLHDSA128sVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_128s, gas: slhdsa128sVerifyGas})
	registry.Register(SLHDSA128fVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_128f, gas: slhdsa128fVerifyGas})
	registry.Register(SLHDSA192sVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_192s, gas: slhdsa192sVerifyGas})
	registry.Register(SLHDSA192fVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_192f, gas: slhdsa192fVerifyGas})
	registry.Register(SLHDSA256sVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_256s, gas: slhdsa256sVerifyGas})
	registry.Register(SLHDSA256fVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_256f, gas: slhdsa256fVerifyGas})
}

func init() {
	RegisterSLHDSA(PostQuantumRegistry)
}
