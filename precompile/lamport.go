// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Lamport one-time signature precompiled contracts
// Ultra-fast quantum-resistant signatures for single-use scenarios

package precompile

import (
	"crypto/sha256"
	"errors"

	// "github.com/luxfi/geth/common" // removed to avoid import cycle
	"github.com/luxfi/crypto/lamport"
)

// Lamport precompile addresses
var (
	LamportVerifySHA256Address = HexToAddress("0x0000000000000000000000000000000000000150")
	LamportVerifySHA512Address = HexToAddress("0x0000000000000000000000000000000000000151")
	LamportBatchVerifyAddress  = HexToAddress("0x0000000000000000000000000000000000000152")
	LamportMerkleRootAddress   = HexToAddress("0x0000000000000000000000000000000000000153")
	LamportMerkleVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000154")
)

// Gas costs for Lamport operations
const (
	lamportVerifySHA256Gas      = 50000
	lamportVerifySHA512Gas      = 80000
	lamportBatchVerifyBaseGas   = 30000
	lamportBatchVerifyPerSigGas = 40000
	lamportMerkleRootGas        = 100000
	lamportMerkleVerifyGas      = 60000
)

// LamportVerifySHA256 implements SHA256-based Lamport verification
type LamportVerifySHA256 struct{}

func (l *LamportVerifySHA256) RequiredGas(input []byte) uint64 {
	return lamportVerifySHA256Gas
}

func (l *LamportVerifySHA256) Run(input []byte) ([]byte, error) {
	// Input: [32 bytes message][signature][public_key]
	if len(input) < 32 {
		return nil, errors.New("input too short")
	}

	message := input[:32]
	remaining := input[32:]

	// Calculate expected sizes
	sigSize := lamport.GetSignatureSize(lamport.SHA256)
	pubKeySize := lamport.GetPublicKeySize(lamport.SHA256)

	if len(remaining) < sigSize+pubKeySize {
		return nil, errors.New("invalid input size")
	}

	sigBytes := remaining[:sigSize]
	pubKeyBytes := remaining[sigSize : sigSize+pubKeySize]

	// Deserialize
	sig, err := lamport.SignatureFromBytes(sigBytes)
	if err != nil {
		return nil, err
	}

	pubKey, err := lamport.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Verify
	valid := pubKey.Verify(message, sig)

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}
	return result, nil
}

// LamportVerifySHA512 implements SHA512-based Lamport verification
type LamportVerifySHA512 struct{}

func (l *LamportVerifySHA512) RequiredGas(input []byte) uint64 {
	return lamportVerifySHA512Gas
}

func (l *LamportVerifySHA512) Run(input []byte) ([]byte, error) {
	// Input: [64 bytes message][signature][public_key]
	if len(input) < 64 {
		return nil, errors.New("input too short")
	}

	message := input[:64]
	remaining := input[64:]

	// Calculate expected sizes
	sigSize := lamport.GetSignatureSize(lamport.SHA512)
	pubKeySize := lamport.GetPublicKeySize(lamport.SHA512)

	if len(remaining) < sigSize+pubKeySize {
		return nil, errors.New("invalid input size")
	}

	sigBytes := remaining[:sigSize]
	pubKeyBytes := remaining[sigSize : sigSize+pubKeySize]

	// Deserialize
	sig, err := lamport.SignatureFromBytes(sigBytes)
	if err != nil {
		return nil, err
	}

	pubKey, err := lamport.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Verify
	valid := pubKey.Verify(message, sig)

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}
	return result, nil
}

// LamportBatchVerify implements batch verification
type LamportBatchVerify struct{}

func (l *LamportBatchVerify) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return lamportBatchVerifyBaseGas
	}
	numSigs := uint64(input[0])
	return lamportBatchVerifyBaseGas + numSigs*lamportBatchVerifyPerSigGas
}

func (l *LamportBatchVerify) Run(input []byte) ([]byte, error) {
	// Input: [1 byte num_sigs][1 byte hash_type][signatures_and_keys...]
	if len(input) < 2 {
		return nil, errors.New("input too short")
	}

	numSigs := input[0]
	hashType := lamport.HashFunc(input[1])

	results := make([]byte, numSigs)
	allValid := true
	offset := 2

	// Get sizes based on hash type
	msgSize := 32
	if hashType == lamport.SHA512 {
		msgSize = 64
	}
	sigSize := lamport.GetSignatureSize(hashType)
	pubKeySize := lamport.GetPublicKeySize(hashType)

	for i := byte(0); i < numSigs; i++ {
		// Check remaining data
		if len(input) < offset+msgSize+sigSize+pubKeySize {
			results[i] = 0x00
			allValid = false
			continue
		}

		// Extract message, signature, and public key
		message := input[offset : offset+msgSize]
		offset += msgSize

		sigBytes := input[offset : offset+sigSize]
		offset += sigSize

		pubKeyBytes := input[offset : offset+pubKeySize]
		offset += pubKeySize

		// Deserialize and verify
		sig, err := lamport.SignatureFromBytes(sigBytes)
		if err != nil {
			results[i] = 0x00
			allValid = false
			continue
		}

		pubKey, err := lamport.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			results[i] = 0x00
			allValid = false
			continue
		}

		if pubKey.Verify(message, sig) {
			results[i] = 0x01
		} else {
			results[i] = 0x00
			allValid = false
		}
	}

	// Return: [overall_valid][individual_results...]
	output := make([]byte, 1+len(results))
	if allValid {
		output[0] = 0x01
	}
	copy(output[1:], results)

	return output, nil
}

// LamportMerkleRoot computes Merkle root of Lamport public keys
type LamportMerkleRoot struct{}

func (l *LamportMerkleRoot) RequiredGas(input []byte) uint64 {
	return lamportMerkleRootGas
}

func (l *LamportMerkleRoot) Run(input []byte) ([]byte, error) {
	// Input: [1 byte num_keys][1 byte hash_type][public_keys...]
	if len(input) < 2 {
		return nil, errors.New("input too short")
	}

	numKeys := input[0]
	hashType := lamport.HashFunc(input[1])

	if numKeys == 0 {
		return nil, errors.New("no keys provided")
	}

	keySize := lamport.GetPublicKeySize(hashType)
	expectedSize := 2 + int(numKeys)*keySize

	if len(input) != expectedSize {
		return nil, errors.New("invalid input size")
	}

	// Hash each public key
	hashes := make([][]byte, numKeys)
	offset := 2

	for i := byte(0); i < numKeys; i++ {
		pubKeyBytes := input[offset : offset+keySize]
		hash := sha256.Sum256(pubKeyBytes)
		hashes[i] = hash[:]
		offset += keySize
	}

	// Compute Merkle root
	root := computeMerkleRoot(hashes)
	return root, nil
}

// LamportMerkleVerify verifies Merkle proof for a Lamport public key
type LamportMerkleVerify struct{}

func (l *LamportMerkleVerify) RequiredGas(input []byte) uint64 {
	return lamportMerkleVerifyGas
}

func (l *LamportMerkleVerify) Run(input []byte) ([]byte, error) {
	// Input: [32 bytes root][1 byte hash_type][public_key][1 byte proof_len][proof...]
	if len(input) < 33 {
		return nil, errors.New("input too short")
	}

	root := input[:32]
	hashType := lamport.HashFunc(input[32])
	remaining := input[33:]

	keySize := lamport.GetPublicKeySize(hashType)
	if len(remaining) < keySize+1 {
		return nil, errors.New("missing public key or proof length")
	}

	pubKeyBytes := remaining[:keySize]
	proofLen := remaining[keySize]
	proofData := remaining[keySize+1:]

	if len(proofData) < int(proofLen)*32 {
		return nil, errors.New("invalid proof")
	}

	// Extract proof hashes
	proof := make([][]byte, proofLen)
	for i := byte(0); i < proofLen; i++ {
		proof[i] = proofData[i*32 : (i+1)*32]
	}

	// Hash the public key
	leafHash := sha256.Sum256(pubKeyBytes)

	// Verify proof
	valid := verifyMerkleProof(root, leafHash[:], proof)

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}
	return result, nil
}

// Helper functions

func computeMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, 32)
	}

	if len(leaves) == 1 {
		return leaves[0]
	}

	currentLevel := leaves

	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, (len(currentLevel)+1)/2)

		for i := 0; i < len(nextLevel); i++ {
			left := currentLevel[i*2]
			var right []byte

			if i*2+1 < len(currentLevel) {
				right = currentLevel[i*2+1]
			} else {
				right = left
			}

			combined := append(left, right...)
			hash := sha256.Sum256(combined)
			nextLevel[i] = hash[:]
		}

		currentLevel = nextLevel
	}

	return currentLevel[0]
}

func verifyMerkleProof(root []byte, leaf []byte, proof [][]byte) bool {
	currentHash := leaf

	for _, sibling := range proof {
		var combined []byte
		if bytesLess(currentHash, sibling) {
			combined = append(currentHash, sibling...)
		} else {
			combined = append(sibling, currentHash...)
		}

		hash := sha256.Sum256(combined)
		currentHash = hash[:]
	}

	return bytesEqual(currentHash, root)
}

func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RegisterLamport registers all Lamport precompiles
func RegisterLamport(registry *Registry) {
	registry.Register(LamportVerifySHA256Address, &LamportVerifySHA256{})
	registry.Register(LamportVerifySHA512Address, &LamportVerifySHA512{})
	registry.Register(LamportBatchVerifyAddress, &LamportBatchVerify{})
	registry.Register(LamportMerkleRootAddress, &LamportMerkleRoot{})
	registry.Register(LamportMerkleVerifyAddress, &LamportMerkleVerify{})
}

func init() {
	// Auto-register Lamport precompiles on package load
	RegisterLamport(PostQuantumRegistry)
}
