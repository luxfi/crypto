// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Package precompile provides EVM precompiled contracts for post-quantum cryptography
// All implementations automatically use CGO when available for performance

package precompile

import (
// "github.com/luxfi/geth/common" // removed to avoid import cycle
)

// PrecompiledContract is the interface for EVM precompiled contracts
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // Calculate gas cost
	Run(input []byte) ([]byte, error) // Execute the precompile
}

// Registry contains all available precompiled contracts
type Registry struct {
	contracts map[Address]PrecompiledContract
	addresses []Address
}

// NewRegistry creates a new precompile registry
func NewRegistry() *Registry {
	return &Registry{
		contracts: make(map[Address]PrecompiledContract),
		addresses: []Address{},
	}
}

// Register adds a precompiled contract to the registry
func (r *Registry) Register(addr Address, contract PrecompiledContract) {
	r.contracts[addr] = contract
	r.addresses = append(r.addresses, addr)
}

// Get returns a precompiled contract by address
func (r *Registry) Get(addr Address) (PrecompiledContract, bool) {
	contract, exists := r.contracts[addr]
	return contract, exists
}

// Addresses returns all registered precompile addresses
func (r *Registry) Addresses() []Address {
	return r.addresses
}

// Contracts returns the map of all contracts
func (r *Registry) Contracts() map[Address]PrecompiledContract {
	return r.contracts
}

// Global registry for all post-quantum precompiles
var PostQuantumRegistry = NewRegistry()

// Address ranges for different crypto standards
const (
	// ML-DSA (FIPS 204) range: 0x0110-0x0119
	MLDSAStartAddress = "0x0110"
	MLDSAEndAddress   = "0x0119"

	// ML-KEM (FIPS 203) range: 0x0120-0x0129
	MLKEMStartAddress = "0x0120"
	MLKEMEndAddress   = "0x0129"

	// SLH-DSA (FIPS 205) range: 0x0130-0x0139
	SLHDSAStartAddress = "0x0130"
	SLHDSAEndAddress   = "0x0139"

	// SHAKE (FIPS 202) range: 0x0140-0x0149
	SHAKEStartAddress = "0x0140"
	SHAKEEndAddress   = "0x0149"

	// Lamport signatures range: 0x0150-0x0159
	LamportStartAddress = "0x0150"
	LamportEndAddress   = "0x0159"
)
