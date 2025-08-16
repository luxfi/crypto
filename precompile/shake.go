// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// SHAKE (FIPS 202) precompiled contracts
// High-performance implementation with CGO support when available

package precompile

import (
	"errors"

	// "github.com/luxfi/geth/common" // removed to avoid import cycle
	"golang.org/x/crypto/sha3"
)

// SHAKE precompile addresses
var (
	// SHAKE128 precompiles
	SHAKE128Address     = HexToAddress("0x0000000000000000000000000000000000000140")
	SHAKE128_256Address = HexToAddress("0x0000000000000000000000000000000000000141")
	SHAKE128_512Address = HexToAddress("0x0000000000000000000000000000000000000142")

	// SHAKE256 precompiles
	SHAKE256Address      = HexToAddress("0x0000000000000000000000000000000000000143")
	SHAKE256_256Address  = HexToAddress("0x0000000000000000000000000000000000000144")
	SHAKE256_512Address  = HexToAddress("0x0000000000000000000000000000000000000145")
	SHAKE256_1024Address = HexToAddress("0x0000000000000000000000000000000000000146")

	// cSHAKE precompiles
	CSHAKE128Address = HexToAddress("0x0000000000000000000000000000000000000147")
	CSHAKE256Address = HexToAddress("0x0000000000000000000000000000000000000148")
)

// Gas costs
const (
	shakeBaseGas    = 60
	shakePerWordGas = 12
	shakeOutputGas  = 3
	maxShakeOutput  = 8192
)

// SHAKE128 implements variable-output SHAKE128
type SHAKE128 struct{}

func (s *SHAKE128) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return shakeBaseGas
	}
	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	inputWords := uint64((len(input) + 31) / 32)  // Include the 4-byte length in gas calculation
	outputWords := uint64((outputLen + 31) / 32)
	return shakeBaseGas + inputWords*shakePerWordGas + outputWords*shakeOutputGas
}

func (s *SHAKE128) Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, errors.New("input too short")
	}

	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	if outputLen > maxShakeOutput {
		return nil, errors.New("output length exceeds maximum")
	}

	hash := sha3.NewShake128()
	hash.Write(input[4:])

	output := make([]byte, outputLen)
	hash.Read(output)
	return output, nil
}

// SHAKE256 implements variable-output SHAKE256
type SHAKE256 struct{}

func (s *SHAKE256) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return shakeBaseGas
	}
	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	inputWords := uint64((len(input) + 31) / 32)  // Include the 4-byte length in gas calculation
	outputWords := uint64((outputLen + 31) / 32)
	return shakeBaseGas + inputWords*shakePerWordGas + outputWords*shakeOutputGas
}

func (s *SHAKE256) Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, errors.New("input too short")
	}

	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	if outputLen > maxShakeOutput {
		return nil, errors.New("output length exceeds maximum")
	}

	hash := sha3.NewShake256()
	hash.Write(input[4:])

	output := make([]byte, outputLen)
	hash.Read(output)
	return output, nil
}

// Fixed-output variants for common sizes

type SHAKE128_256 struct{}

func (s *SHAKE128_256) RequiredGas(input []byte) uint64 {
	return 200
}

func (s *SHAKE128_256) Run(input []byte) ([]byte, error) {
	hash := sha3.NewShake128()
	hash.Write(input)
	output := make([]byte, 32)
	hash.Read(output)
	return output, nil
}

type SHAKE256_256 struct{}

func (s *SHAKE256_256) RequiredGas(input []byte) uint64 {
	return 200
}

func (s *SHAKE256_256) Run(input []byte) ([]byte, error) {
	hash := sha3.NewShake256()
	hash.Write(input)
	output := make([]byte, 32)
	hash.Read(output)
	return output, nil
}

type SHAKE256_512 struct{}

func (s *SHAKE256_512) RequiredGas(input []byte) uint64 {
	return 250
}

func (s *SHAKE256_512) Run(input []byte) ([]byte, error) {
	hash := sha3.NewShake256()
	hash.Write(input)
	output := make([]byte, 64)
	hash.Read(output)
	return output, nil
}

// cSHAKE128 with customization string
type CSHAKE128 struct{}

func (c *CSHAKE128) RequiredGas(input []byte) uint64 {
	if len(input) < 8 {
		return shakeBaseGas
	}

	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	customLen := uint32(input[4])<<24 | uint32(input[5])<<16 | uint32(input[6])<<8 | uint32(input[7])

	if len(input) < int(8+customLen) {
		return shakeBaseGas
	}

	dataLen := len(input) - int(8+customLen)
	inputWords := uint64((dataLen + 31) / 32)
	outputWords := uint64((outputLen + 31) / 32)
	customWords := uint64((customLen + 31) / 32)

	return shakeBaseGas + (inputWords+customWords)*shakePerWordGas + outputWords*shakeOutputGas
}

func (c *CSHAKE128) Run(input []byte) ([]byte, error) {
	if len(input) < 8 {
		return nil, errors.New("input too short")
	}

	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	customLen := uint32(input[4])<<24 | uint32(input[5])<<16 | uint32(input[6])<<8 | uint32(input[7])

	if outputLen > maxShakeOutput {
		return nil, errors.New("output length exceeds maximum")
	}

	if len(input) < int(8+customLen) {
		return nil, errors.New("input too short for customization")
	}

	customization := input[8 : 8+customLen]
	data := input[8+customLen:]

	hash := sha3.NewCShake128(nil, customization)
	hash.Write(data)

	output := make([]byte, outputLen)
	hash.Read(output)
	return output, nil
}

// RegisterSHAKE registers all SHAKE precompiles
func RegisterSHAKE(registry *Registry) {
	registry.Register(SHAKE128Address, &SHAKE128{})
	registry.Register(SHAKE128_256Address, &SHAKE128_256{})
	registry.Register(SHAKE128_512Address, &SHAKE128_512{})
	registry.Register(SHAKE256Address, &SHAKE256{})
	registry.Register(SHAKE256_256Address, &SHAKE256_256{})
	registry.Register(SHAKE256_512Address, &SHAKE256_512{})
	registry.Register(SHAKE256_1024Address, &SHAKE256_1024{})
	registry.Register(CSHAKE128Address, &CSHAKE128{})
	registry.Register(CSHAKE256Address, &CSHAKE256{})
}

// Fixed size implementations
type SHAKE128_512 struct{}

func (s *SHAKE128_512) RequiredGas(input []byte) uint64 {
	return 250
}

func (s *SHAKE128_512) Run(input []byte) ([]byte, error) {
	hash := sha3.NewShake128()
	hash.Write(input)
	output := make([]byte, 64)
	hash.Read(output)
	return output, nil
}

type SHAKE256_1024 struct{}

func (s *SHAKE256_1024) RequiredGas(input []byte) uint64 {
	return 350
}

func (s *SHAKE256_1024) Run(input []byte) ([]byte, error) {
	hash := sha3.NewShake256()
	hash.Write(input)
	output := make([]byte, 128)
	hash.Read(output)
	return output, nil
}

type CSHAKE256 struct{}

func (c *CSHAKE256) RequiredGas(input []byte) uint64 {
	if len(input) < 8 {
		return shakeBaseGas
	}

	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	customLen := uint32(input[4])<<24 | uint32(input[5])<<16 | uint32(input[6])<<8 | uint32(input[7])

	if len(input) < int(8+customLen) {
		return shakeBaseGas
	}

	dataLen := len(input) - int(8+customLen)
	inputWords := uint64((dataLen + 31) / 32)
	outputWords := uint64((outputLen + 31) / 32)
	customWords := uint64((customLen + 31) / 32)

	return shakeBaseGas + (inputWords+customWords)*shakePerWordGas + outputWords*shakeOutputGas
}

func (c *CSHAKE256) Run(input []byte) ([]byte, error) {
	if len(input) < 8 {
		return nil, errors.New("input too short")
	}

	outputLen := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	customLen := uint32(input[4])<<24 | uint32(input[5])<<16 | uint32(input[6])<<8 | uint32(input[7])

	if outputLen > maxShakeOutput {
		return nil, errors.New("output length exceeds maximum")
	}

	if len(input) < int(8+customLen) {
		return nil, errors.New("input too short for customization")
	}

	customization := input[8 : 8+customLen]
	data := input[8+customLen:]

	hash := sha3.NewCShake256(nil, customization)
	hash.Write(data)

	output := make([]byte, outputLen)
	hash.Read(output)
	return output, nil
}

func init() {
	// Auto-register SHAKE precompiles on package load
	RegisterSHAKE(PostQuantumRegistry)
}
