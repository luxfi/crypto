// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// SLH-DSA (FIPS 205) precompiled contracts for EVM
// Provides on-chain post-quantum stateless hash-based signature verification

package precompile

import (
	"crypto/rand"
	"errors"

	"github.com/luxfi/crypto/slhdsa"
)

// SLH-DSA precompile addresses (0x0130-0x0139)
var (
	SLHDSA128sVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000130")
	SLHDSA128fVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000131")
	SLHDSA192sVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000132")
	SLHDSA192fVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000133")
	SLHDSA256sVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000134")
	SLHDSA256fVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000135")
	SLHDSA128sSignAddress   = HexToAddress("0x0000000000000000000000000000000000000136")
	SLHDSA192sSignAddress   = HexToAddress("0x0000000000000000000000000000000000000137")
	SLHDSA256sSignAddress   = HexToAddress("0x0000000000000000000000000000000000000138")
)

// Gas costs for SLH-DSA operations
const (
	slhdsa128sVerifyGas = 300000
	slhdsa128fVerifyGas = 200000
	slhdsa192sVerifyGas = 400000
	slhdsa192fVerifyGas = 300000
	slhdsa256sVerifyGas = 500000
	slhdsa256fVerifyGas = 400000
	slhdsaSignGas       = 1000000
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

// slhdsaSign implements SLH-DSA signing for a given mode.
type slhdsaSign struct {
	mode slhdsa.Mode
	gas  uint64
}

func (s *slhdsaSign) RequiredGas(input []byte) uint64 { return s.gas }

func (s *slhdsaSign) Run(input []byte) ([]byte, error) {
	// Input: [private_key_bytes][message]
	// SLH-DSA private keys are mode-dependent in size; we need the full
	// serialized private key as produced by PrivateKey.Bytes().
	// Since we don't have a PrivateKeyFromBytes that detects size, callers
	// must provide the correctly-sized key for the mode.
	pubKeySize := slhdsa.GetPublicKeySize(s.mode)
	if pubKeySize == 0 {
		return nil, errors.New("invalid SLH-DSA mode")
	}

	// SLH-DSA private key is 4*n bytes where n depends on security level:
	// 128-bit: n=16 -> 64 bytes, 192-bit: n=24 -> 96 bytes, 256-bit: n=32 -> 128 bytes
	var privKeySize int
	switch s.mode {
	case slhdsa.SHA2_128s, slhdsa.SHAKE_128s, slhdsa.SHA2_128f, slhdsa.SHAKE_128f:
		privKeySize = 64
	case slhdsa.SHA2_192s, slhdsa.SHAKE_192s, slhdsa.SHA2_192f, slhdsa.SHAKE_192f:
		privKeySize = 96
	case slhdsa.SHA2_256s, slhdsa.SHAKE_256s, slhdsa.SHA2_256f, slhdsa.SHAKE_256f:
		privKeySize = 128
	default:
		return nil, errors.New("invalid SLH-DSA mode")
	}

	if len(input) < privKeySize+1 {
		return nil, errors.New("input too short")
	}

	privKeyBytes := input[:privKeySize]
	message := input[privKeySize:]

	privKey, err := slhdsa.PrivateKeyFromBytes(s.mode, privKeyBytes)
	if err != nil {
		return nil, err
	}

	return privKey.Sign(rand.Reader, message, nil)
}

// RegisterSLHDSA registers all SLH-DSA precompiles.
func RegisterSLHDSA(registry *Registry) {
	// Verification precompiles (small and fast variants)
	registry.Register(SLHDSA128sVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_128s, gas: slhdsa128sVerifyGas})
	registry.Register(SLHDSA128fVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_128f, gas: slhdsa128fVerifyGas})
	registry.Register(SLHDSA192sVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_192s, gas: slhdsa192sVerifyGas})
	registry.Register(SLHDSA192fVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_192f, gas: slhdsa192fVerifyGas})
	registry.Register(SLHDSA256sVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_256s, gas: slhdsa256sVerifyGas})
	registry.Register(SLHDSA256fVerifyAddress, &slhdsaVerify{mode: slhdsa.SHA2_256f, gas: slhdsa256fVerifyGas})

	// Signing precompiles (small signature variants only -- fast variants are for
	// off-chain use where gas is irrelevant)
	registry.Register(SLHDSA128sSignAddress, &slhdsaSign{mode: slhdsa.SHA2_128s, gas: slhdsaSignGas})
	registry.Register(SLHDSA192sSignAddress, &slhdsaSign{mode: slhdsa.SHA2_192s, gas: slhdsaSignGas})
	registry.Register(SLHDSA256sSignAddress, &slhdsaSign{mode: slhdsa.SHA2_256s, gas: slhdsaSignGas})
}

func init() {
	RegisterSLHDSA(PostQuantumRegistry)
}
