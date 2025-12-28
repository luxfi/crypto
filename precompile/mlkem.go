// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// ML-KEM (FIPS 203) precompiled contracts for EVM
// Provides on-chain post-quantum key encapsulation

package precompile

import (
	"errors"

	"github.com/luxfi/crypto/mlkem"
)

// ML-KEM precompile addresses (0x0120-0x0129)
var (
	MLKEM512EncapsulateAddress  = HexToAddress("0x0000000000000000000000000000000000000120")
	MLKEM768EncapsulateAddress  = HexToAddress("0x0000000000000000000000000000000000000121")
	MLKEM1024EncapsulateAddress = HexToAddress("0x0000000000000000000000000000000000000122")
	MLKEM512DecapsulateAddress  = HexToAddress("0x0000000000000000000000000000000000000123")
	MLKEM768DecapsulateAddress  = HexToAddress("0x0000000000000000000000000000000000000124")
	MLKEM1024DecapsulateAddress = HexToAddress("0x0000000000000000000000000000000000000125")
	MLKEM512KeyGenAddress       = HexToAddress("0x0000000000000000000000000000000000000126")
	MLKEM768KeyGenAddress       = HexToAddress("0x0000000000000000000000000000000000000127")
	MLKEM1024KeyGenAddress      = HexToAddress("0x0000000000000000000000000000000000000128")
)

// Gas costs for ML-KEM operations
const (
	mlkem512EncapsulateGas  = 80000
	mlkem768EncapsulateGas  = 100000
	mlkem1024EncapsulateGas = 130000
	mlkem512DecapsulateGas  = 80000
	mlkem768DecapsulateGas  = 100000
	mlkem1024DecapsulateGas = 130000
	mlkemKeyGenGas          = 200000
)

// mlkemEncapsulate implements ML-KEM encapsulation for a given mode.
type mlkemEncapsulate struct {
	mode mlkem.Mode
	gas  uint64
}

func (e *mlkemEncapsulate) RequiredGas(input []byte) uint64 { return e.gas }

func (e *mlkemEncapsulate) Run(input []byte) ([]byte, error) {
	// Input: [encapsulation_key]
	expectedSize := mlkem.GetPublicKeySize(e.mode)
	if len(input) != expectedSize {
		return nil, errors.New("invalid encapsulation key size")
	}

	pk, err := mlkem.PublicKeyFromBytes(input, e.mode)
	if err != nil {
		return nil, err
	}

	ciphertext, sharedKey, err := pk.Encapsulate()
	if err != nil {
		return nil, err
	}

	// Output: [shared_key (32)][ciphertext]
	result := make([]byte, len(sharedKey)+len(ciphertext))
	copy(result, sharedKey)
	copy(result[len(sharedKey):], ciphertext)
	return result, nil
}

// mlkemDecapsulate implements ML-KEM decapsulation for a given mode.
type mlkemDecapsulate struct {
	mode mlkem.Mode
	gas  uint64
}

func (d *mlkemDecapsulate) RequiredGas(input []byte) uint64 { return d.gas }

func (d *mlkemDecapsulate) Run(input []byte) ([]byte, error) {
	// Input: [private_key][ciphertext]
	privKeySize := mlkem.GetPrivateKeySize(d.mode)
	ctSize := mlkem.GetCiphertextSize(d.mode)

	if len(input) != privKeySize+ctSize {
		return nil, errors.New("invalid input size")
	}

	privKeyBytes := input[:privKeySize]
	ciphertext := input[privKeySize:]

	sk, err := mlkem.PrivateKeyFromBytes(privKeyBytes, d.mode)
	if err != nil {
		return nil, err
	}

	return sk.Decapsulate(ciphertext)
}

// mlkemKeyGen implements ML-KEM key pair generation for a given mode.
type mlkemKeyGen struct {
	mode mlkem.Mode
}

func (k *mlkemKeyGen) RequiredGas(input []byte) uint64 { return mlkemKeyGenGas }

func (k *mlkemKeyGen) Run(input []byte) ([]byte, error) {
	pk, sk, err := mlkem.GenerateKey(k.mode)
	if err != nil {
		return nil, err
	}

	pubBytes := pk.Bytes()
	privBytes := sk.Bytes()

	// Output: [public_key][private_key]
	result := make([]byte, len(pubBytes)+len(privBytes))
	copy(result, pubBytes)
	copy(result[len(pubBytes):], privBytes)
	return result, nil
}

// RegisterMLKEM registers all ML-KEM precompiles.
func RegisterMLKEM(registry *Registry) {
	registry.Register(MLKEM512EncapsulateAddress, &mlkemEncapsulate{mode: mlkem.MLKEM512, gas: mlkem512EncapsulateGas})
	registry.Register(MLKEM768EncapsulateAddress, &mlkemEncapsulate{mode: mlkem.MLKEM768, gas: mlkem768EncapsulateGas})
	registry.Register(MLKEM1024EncapsulateAddress, &mlkemEncapsulate{mode: mlkem.MLKEM1024, gas: mlkem1024EncapsulateGas})
	registry.Register(MLKEM512DecapsulateAddress, &mlkemDecapsulate{mode: mlkem.MLKEM512, gas: mlkem512DecapsulateGas})
	registry.Register(MLKEM768DecapsulateAddress, &mlkemDecapsulate{mode: mlkem.MLKEM768, gas: mlkem768DecapsulateGas})
	registry.Register(MLKEM1024DecapsulateAddress, &mlkemDecapsulate{mode: mlkem.MLKEM1024, gas: mlkem1024DecapsulateGas})
	registry.Register(MLKEM512KeyGenAddress, &mlkemKeyGen{mode: mlkem.MLKEM512})
	registry.Register(MLKEM768KeyGenAddress, &mlkemKeyGen{mode: mlkem.MLKEM768})
	registry.Register(MLKEM1024KeyGenAddress, &mlkemKeyGen{mode: mlkem.MLKEM1024})
}

func init() {
	RegisterMLKEM(PostQuantumRegistry)
}
