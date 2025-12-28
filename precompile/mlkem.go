// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// ML-KEM (FIPS 203) precompiled contracts for EVM
// Provides on-chain post-quantum key encapsulation
//
// SECURITY: Only encapsulation (public-key operation) is exposed. Decapsulation
// and keygen are deliberately excluded — private key material must never appear
// in EVM calldata (it is visible to all nodes and permanently stored on-chain).

package precompile

import (
	"errors"

	"github.com/luxfi/crypto/mlkem"
)

// ML-KEM encapsulation precompile addresses (0x0120-0x0122)
var (
	MLKEM512EncapsulateAddress  = HexToAddress("0x0000000000000000000000000000000000000120")
	MLKEM768EncapsulateAddress  = HexToAddress("0x0000000000000000000000000000000000000121")
	MLKEM1024EncapsulateAddress = HexToAddress("0x0000000000000000000000000000000000000122")
)

// Gas costs for ML-KEM encapsulation
const (
	mlkem512EncapsulateGas  = 80000
	mlkem768EncapsulateGas  = 100000
	mlkem1024EncapsulateGas = 130000
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

// RegisterMLKEM registers ML-KEM encapsulation precompiles.
func RegisterMLKEM(registry *Registry) {
	registry.Register(MLKEM512EncapsulateAddress, &mlkemEncapsulate{mode: mlkem.MLKEM512, gas: mlkem512EncapsulateGas})
	registry.Register(MLKEM768EncapsulateAddress, &mlkemEncapsulate{mode: mlkem.MLKEM768, gas: mlkem768EncapsulateGas})
	registry.Register(MLKEM1024EncapsulateAddress, &mlkemEncapsulate{mode: mlkem.MLKEM1024, gas: mlkem1024EncapsulateGas})
}

func init() {
	RegisterMLKEM(PostQuantumRegistry)
}
