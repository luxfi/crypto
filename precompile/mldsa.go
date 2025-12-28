// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// ML-DSA (FIPS 204) precompiled contracts for EVM
// Provides on-chain post-quantum signature verification

package precompile

import (
	"crypto/rand"
	"errors"

	"github.com/luxfi/crypto/mldsa"
)

// ML-DSA precompile addresses (0x0110-0x0119)
var (
	MLDSA44VerifyAddress  = HexToAddress("0x0000000000000000000000000000000000000110")
	MLDSA65VerifyAddress  = HexToAddress("0x0000000000000000000000000000000000000111")
	MLDSA87VerifyAddress  = HexToAddress("0x0000000000000000000000000000000000000112")
	MLDSA44SignAddress    = HexToAddress("0x0000000000000000000000000000000000000113")
	MLDSA65SignAddress    = HexToAddress("0x0000000000000000000000000000000000000114")
	MLDSA87SignAddress    = HexToAddress("0x0000000000000000000000000000000000000115")
	MLDSA44KeyGenAddress  = HexToAddress("0x0000000000000000000000000000000000000116")
	MLDSA65KeyGenAddress  = HexToAddress("0x0000000000000000000000000000000000000117")
	MLDSA87KeyGenAddress  = HexToAddress("0x0000000000000000000000000000000000000118")
)

// Gas costs for ML-DSA operations
const (
	mldsa44VerifyGas = 120000
	mldsa65VerifyGas = 180000
	mldsa87VerifyGas = 250000
	mldsa44SignGas   = 200000
	mldsa65SignGas   = 300000
	mldsa87SignGas   = 400000
	mldsaKeyGenGas   = 500000
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

// mldsaSign implements ML-DSA signing for a given mode.
type mldsaSign struct {
	mode mldsa.Mode
	gas  uint64
}

func (s *mldsaSign) RequiredGas(input []byte) uint64 { return s.gas }

func (s *mldsaSign) Run(input []byte) ([]byte, error) {
	// Input: [private_key][message]
	privKeySize := 0
	switch s.mode {
	case mldsa.MLDSA44:
		privKeySize = mldsa.MLDSA44PrivateKeySize
	case mldsa.MLDSA65:
		privKeySize = mldsa.MLDSA65PrivateKeySize
	case mldsa.MLDSA87:
		privKeySize = mldsa.MLDSA87PrivateKeySize
	default:
		return nil, errors.New("invalid ML-DSA mode")
	}

	if len(input) < privKeySize+1 {
		return nil, errors.New("input too short")
	}

	privKeyBytes := input[:privKeySize]
	message := input[privKeySize:]

	privKey, err := mldsa.PrivateKeyFromBytes(s.mode, privKeyBytes)
	if err != nil {
		return nil, err
	}

	return privKey.Sign(rand.Reader, message, nil)
}

// mldsaKeyGen implements ML-DSA key pair generation for a given mode.
type mldsaKeyGen struct {
	mode mldsa.Mode
}

func (k *mldsaKeyGen) RequiredGas(input []byte) uint64 { return mldsaKeyGenGas }

func (k *mldsaKeyGen) Run(input []byte) ([]byte, error) {
	privKey, err := mldsa.GenerateKey(rand.Reader, k.mode)
	if err != nil {
		return nil, err
	}

	pubBytes := privKey.PublicKey.Bytes()
	privBytes := privKey.Bytes()

	// Output: [public_key][private_key]
	result := make([]byte, len(pubBytes)+len(privBytes))
	copy(result, pubBytes)
	copy(result[len(pubBytes):], privBytes)
	return result, nil
}

// RegisterMLDSA registers all ML-DSA precompiles.
func RegisterMLDSA(registry *Registry) {
	registry.Register(MLDSA44VerifyAddress, &mldsaVerify{mode: mldsa.MLDSA44, gas: mldsa44VerifyGas})
	registry.Register(MLDSA65VerifyAddress, &mldsaVerify{mode: mldsa.MLDSA65, gas: mldsa65VerifyGas})
	registry.Register(MLDSA87VerifyAddress, &mldsaVerify{mode: mldsa.MLDSA87, gas: mldsa87VerifyGas})
	registry.Register(MLDSA44SignAddress, &mldsaSign{mode: mldsa.MLDSA44, gas: mldsa44SignGas})
	registry.Register(MLDSA65SignAddress, &mldsaSign{mode: mldsa.MLDSA65, gas: mldsa65SignGas})
	registry.Register(MLDSA87SignAddress, &mldsaSign{mode: mldsa.MLDSA87, gas: mldsa87SignGas})
	registry.Register(MLDSA44KeyGenAddress, &mldsaKeyGen{mode: mldsa.MLDSA44})
	registry.Register(MLDSA65KeyGenAddress, &mldsaKeyGen{mode: mldsa.MLDSA65})
	registry.Register(MLDSA87KeyGenAddress, &mldsaKeyGen{mode: mldsa.MLDSA87})
}

func init() {
	RegisterMLDSA(PostQuantumRegistry)
}
