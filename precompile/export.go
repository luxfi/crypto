// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Package precompile exports all post-quantum cryptography precompiles
// for easy integration into EVM implementations

package precompile

import (
// "github.com/luxfi/geth/common" // removed to avoid import cycle
)

// GetAllPostQuantumPrecompiles returns all post-quantum precompiles
// This includes SHAKE, Lamport, and the three NIST standards
func GetAllPostQuantumPrecompiles() map[Address]PrecompiledContract {
	registry := NewRegistry()

	// Register all precompile types
	RegisterSHAKE(registry)
	RegisterLamport(registry)
	// ML-DSA, ML-KEM, SLH-DSA would be registered here when moved to this package

	return registry.Contracts()
}

// GetPrecompileAddresses returns all registered addresses
func GetPrecompileAddresses() []Address {
	return PostQuantumRegistry.Addresses()
}

// EnableCGO checks if CGO optimizations are available
func EnableCGO() bool {
	// This will be determined at build time
	// CGO implementations will override this
	return false
}

// GetGasEstimate returns an estimated gas cost for a precompile
func GetGasEstimate(addr Address, inputSize int) uint64 {
	contract, exists := PostQuantumRegistry.Get(addr)
	if !exists {
		return 0
	}

	// Create dummy input of the specified size for estimation
	dummyInput := make([]byte, inputSize)
	return contract.RequiredGas(dummyInput)
}

// Info returns information about all registered precompiles
func Info() map[string]interface{} {
	return map[string]interface{}{
		"total_precompiles": len(PostQuantumRegistry.Addresses()),
		"cgo_enabled":       EnableCGO(),
		"standards": []string{
			"FIPS 202 (SHAKE)",
			"FIPS 203 (ML-KEM)",
			"FIPS 204 (ML-DSA)",
			"FIPS 205 (SLH-DSA)",
			"Lamport OTS",
		},
		"address_ranges": map[string]string{
			"ml_dsa":  "0x0110-0x0119",
			"ml_kem":  "0x0120-0x0129",
			"slh_dsa": "0x0130-0x0139",
			"shake":   "0x0140-0x0149",
			"lamport": "0x0150-0x0159",
		},
		"shake_precompiles": []string{
			"SHAKE128 (variable)",
			"SHAKE128-256",
			"SHAKE128-512",
			"SHAKE256 (variable)",
			"SHAKE256-256",
			"SHAKE256-512",
			"SHAKE256-1024",
			"cSHAKE128",
			"cSHAKE256",
		},
		"lamport_precompiles": []string{
			"Verify SHA256",
			"Verify SHA512",
			"Batch Verify",
			"Merkle Root",
			"Merkle Verify",
		},
	}
}
