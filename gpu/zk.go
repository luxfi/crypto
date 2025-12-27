// Package gpu provides GPU-accelerated ZK cryptographic operations.
//
// This package wraps github.com/luxfi/gpu for unified GPU support:
//   - Metal (Apple Silicon via MLX)
//   - CUDA (NVIDIA via MLX)
//   - CPU fallback (gnark-crypto)
//
// Operations:
//   - Poseidon2 hash (BN254/Fr) for Merkle trees
//   - Multi-scalar multiplication (MSM) for commitments
//   - Batch commitment/nullifier operations
//
// Threshold-gated routing:
//   - Below threshold: CPU (lower latency)
//   - Above threshold: GPU (higher throughput)
package gpu

import (
	"encoding/binary"
	"errors"
	"sync"

	luxgpu "github.com/luxfi/gpu"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	gnarkHash "github.com/consensys/gnark-crypto/hash"
)

// =============================================================================
// Threshold Constants
// =============================================================================

const (
	// ThresholdPoseidon2 is the minimum batch size for GPU Poseidon2 hashing.
	ThresholdPoseidon2 = 64

	// ThresholdMerkle is the minimum leaf pairs for GPU Merkle layer.
	ThresholdMerkle = 128

	// ThresholdMSM is the minimum point-scalar pairs for GPU MSM.
	ThresholdMSM = 256

	// ThresholdCommitment is the minimum batch size for GPU commitments.
	ThresholdCommitment = 128

	// ThresholdFRI is the minimum evaluations for GPU FRI folding.
	ThresholdFRI = 512
)

// =============================================================================
// Error Types
// =============================================================================

var (
	ErrInvalidInput   = errors.New("invalid input")
	ErrSizeMismatch   = errors.New("input size mismatch")
	ErrNotPowerOfTwo  = errors.New("size must be power of two")
	ErrGPUUnavailable = errors.New("GPU acceleration unavailable")
)

// =============================================================================
// Field Element Type (BN254 Fr - 256-bit)
// =============================================================================

// Fr256 represents a 256-bit field element (BN254 scalar field).
// Uses 4 x 64-bit limbs in little-endian order.
type Fr256 = luxgpu.Fr256

// =============================================================================
// ZK Context
// =============================================================================

// ZKContext provides GPU-accelerated ZK operations with automatic routing.
type ZKContext struct {
	mu         sync.RWMutex
	gpuEnabled bool
	deviceName string

	// Stats for monitoring
	gpuCalls int64
	cpuCalls int64
}

// DefaultZKContext is the global ZK context (lazy initialized).
var (
	defaultZKContext *ZKContext
	initOnce         sync.Once
)

// GetZKContext returns the global ZK context.
func GetZKContext() *ZKContext {
	initOnce.Do(func() {
		gpuEnabled := luxgpu.ZKGPUAvailable()
		deviceName := luxgpu.ZKGetBackend()
		if !gpuEnabled {
			deviceName = "CPU (gnark-crypto)"
		}
		defaultZKContext = &ZKContext{
			gpuEnabled: gpuEnabled,
			deviceName: deviceName,
		}
	})
	return defaultZKContext
}

// GPUEnabled returns true if GPU acceleration is enabled.
func (z *ZKContext) GPUEnabled() bool {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.gpuEnabled
}

// DeviceName returns the GPU device name.
func (z *ZKContext) DeviceName() string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.deviceName
}

// Stats returns GPU/CPU call statistics.
func (z *ZKContext) Stats() (gpuCalls, cpuCalls int64) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.gpuCalls, z.cpuCalls
}

// =============================================================================
// Poseidon2 Hash Operations (CPU Implementation - gnark-crypto)
// =============================================================================

// poseidon2HasherPool is a pool of Poseidon2 hashers for concurrent use.
var poseidon2HasherPool = sync.Pool{
	New: func() interface{} {
		return poseidon2.NewMerkleDamgardHasher()
	},
}

// poseidon2HashPairCPU computes Poseidon2(left, right) using gnark-crypto.
func poseidon2HashPairCPU(left, right *Fr256) Fr256 {
	h := poseidon2HasherPool.Get().(gnarkHash.StateStorer)
	defer poseidon2HasherPool.Put(h)

	h.Reset()

	// Write left and right as bytes
	leftBytes := fr256ToBytes(left)
	rightBytes := fr256ToBytes(right)

	_, _ = h.Write(leftBytes)
	_, _ = h.Write(rightBytes)

	// Get the hash result
	resultBytes := h.Sum(nil)

	// Convert back to Fr256
	var out Fr256
	_ = fr256FromBytes(&out, resultBytes[:32])
	return out
}

// fr256ToBytes converts Fr256 to 32-byte big-endian slice.
func fr256ToBytes(f *Fr256) []byte {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint64(buf[0:8], f[3])
	binary.BigEndian.PutUint64(buf[8:16], f[2])
	binary.BigEndian.PutUint64(buf[16:24], f[1])
	binary.BigEndian.PutUint64(buf[24:32], f[0])
	return buf
}

// fr256FromBytes sets Fr256 from 32-byte big-endian slice.
func fr256FromBytes(f *Fr256, buf []byte) error {
	if len(buf) != 32 {
		return ErrInvalidInput
	}
	f[3] = binary.BigEndian.Uint64(buf[0:8])
	f[2] = binary.BigEndian.Uint64(buf[8:16])
	f[1] = binary.BigEndian.Uint64(buf[16:24])
	f[0] = binary.BigEndian.Uint64(buf[24:32])
	return nil
}

// =============================================================================
// Public API - Poseidon2
// =============================================================================

// Poseidon2HashPair computes Poseidon2(left, right) with automatic routing.
func (z *ZKContext) Poseidon2HashPair(left, right *Fr256) Fr256 {
	// Single hash always uses CPU (GPU overhead not worth it)
	z.mu.Lock()
	z.cpuCalls++
	z.mu.Unlock()
	return poseidon2HashPairCPU(left, right)
}

// Poseidon2BatchHashPair computes batch Poseidon2 hashes with threshold routing.
func (z *ZKContext) Poseidon2BatchHashPair(left, right []Fr256) ([]Fr256, error) {
	n := len(left)
	if n != len(right) {
		return nil, ErrSizeMismatch
	}
	if n == 0 {
		return nil, nil
	}

	// Check threshold for GPU routing
	if z.GPUEnabled() && n >= ThresholdPoseidon2 {
		z.mu.Lock()
		z.gpuCalls++
		z.mu.Unlock()
		return luxgpu.Poseidon2Hash(left, right)
	}

	// CPU path using gnark-crypto
	z.mu.Lock()
	z.cpuCalls++
	z.mu.Unlock()

	result := make([]Fr256, n)
	for i := 0; i < n; i++ {
		result[i] = poseidon2HashPairCPU(&left[i], &right[i])
	}

	return result, nil
}

// =============================================================================
// Poseidon2 Merkle Tree Operations
// =============================================================================

// Poseidon2MerkleLayer computes one layer of a Merkle tree.
func (z *ZKContext) Poseidon2MerkleLayer(nodes []Fr256) ([]Fr256, error) {
	n := len(nodes)
	if n == 0 || n%2 != 0 {
		return nil, ErrInvalidInput
	}

	parentCount := n / 2

	// Check threshold for GPU routing
	if z.GPUEnabled() && parentCount >= ThresholdMerkle {
		z.mu.Lock()
		z.gpuCalls++
		z.mu.Unlock()
		return luxgpu.MerkleLayer(nodes)
	}

	// CPU path
	z.mu.Lock()
	z.cpuCalls++
	z.mu.Unlock()

	parents := make([]Fr256, parentCount)
	for i := 0; i < parentCount; i++ {
		parents[i] = poseidon2HashPairCPU(&nodes[i*2], &nodes[i*2+1])
	}

	return parents, nil
}

// Poseidon2MerkleRoot computes the Merkle root from leaves.
func (z *ZKContext) Poseidon2MerkleRoot(leaves []Fr256) (Fr256, error) {
	n := len(leaves)
	if n == 0 || (n&(n-1)) != 0 {
		return Fr256{}, ErrNotPowerOfTwo
	}

	if n == 1 {
		return leaves[0], nil
	}

	// Use GPU if available and above threshold
	if z.GPUEnabled() && n >= ThresholdMerkle*2 {
		z.mu.Lock()
		z.gpuCalls++
		z.mu.Unlock()
		return luxgpu.MerkleRoot(leaves)
	}

	// CPU path - build tree layer by layer
	current := leaves
	for len(current) > 1 {
		next, err := z.Poseidon2MerkleLayer(current)
		if err != nil {
			return Fr256{}, err
		}
		current = next
	}

	return current[0], nil
}

// Poseidon2MerkleTree builds a complete Merkle tree.
func (z *ZKContext) Poseidon2MerkleTree(leaves []Fr256) ([]Fr256, error) {
	n := len(leaves)
	if n == 0 || (n&(n-1)) != 0 {
		return nil, ErrNotPowerOfTwo
	}

	if n == 1 {
		return []Fr256{leaves[0]}, nil
	}

	// Use GPU if available and above threshold
	if z.GPUEnabled() && n >= ThresholdMerkle*2 {
		z.mu.Lock()
		z.gpuCalls++
		z.mu.Unlock()
		return luxgpu.MerkleTree(leaves)
	}

	// CPU path - collect all internal nodes
	allNodes := make([]Fr256, 0, n-1)
	current := leaves

	for len(current) > 1 {
		next, err := z.Poseidon2MerkleLayer(current)
		if err != nil {
			return nil, err
		}
		allNodes = append(allNodes, next...)
		current = next
	}

	return allNodes, nil
}

// =============================================================================
// Commitment and Nullifier Operations
// =============================================================================

// Poseidon2Commitment computes commitment = Poseidon2(Poseidon2(value, blinding), salt).
func (z *ZKContext) Poseidon2Commitment(value, blinding, salt *Fr256) Fr256 {
	intermediate := poseidon2HashPairCPU(value, blinding)
	return poseidon2HashPairCPU(&intermediate, salt)
}

// Poseidon2Nullifier computes nullifier = Poseidon2(Poseidon2(key, commitment), index).
func (z *ZKContext) Poseidon2Nullifier(key, commitment, index *Fr256) Fr256 {
	intermediate := poseidon2HashPairCPU(key, commitment)
	return poseidon2HashPairCPU(&intermediate, index)
}

// BatchCommitment computes batch commitments with threshold routing.
func (z *ZKContext) BatchCommitment(values, blindings, salts []Fr256) ([]Fr256, error) {
	n := len(values)
	if n != len(blindings) || n != len(salts) {
		return nil, ErrSizeMismatch
	}
	if n == 0 {
		return nil, nil
	}

	// Check threshold for GPU routing
	if z.GPUEnabled() && n >= ThresholdCommitment {
		z.mu.Lock()
		z.gpuCalls++
		z.mu.Unlock()
		return luxgpu.BatchCommitment(values, blindings, salts)
	}

	// CPU path
	z.mu.Lock()
	z.cpuCalls++
	z.mu.Unlock()

	result := make([]Fr256, n)
	for i := 0; i < n; i++ {
		result[i] = z.Poseidon2Commitment(&values[i], &blindings[i], &salts[i])
	}

	return result, nil
}

// BatchNullifier computes batch nullifiers with threshold routing.
func (z *ZKContext) BatchNullifier(keys, commitments, indices []Fr256) ([]Fr256, error) {
	n := len(keys)
	if n != len(commitments) || n != len(indices) {
		return nil, ErrSizeMismatch
	}
	if n == 0 {
		return nil, nil
	}

	// Check threshold for GPU routing
	if z.GPUEnabled() && n >= ThresholdCommitment {
		z.mu.Lock()
		z.gpuCalls++
		z.mu.Unlock()
		return luxgpu.BatchNullifier(keys, commitments, indices)
	}

	// CPU path
	z.mu.Lock()
	z.cpuCalls++
	z.mu.Unlock()

	result := make([]Fr256, n)
	for i := 0; i < n; i++ {
		result[i] = z.Poseidon2Nullifier(&keys[i], &commitments[i], &indices[i])
	}

	return result, nil
}

// =============================================================================
// Convenience Functions (use default context)
// =============================================================================

// Poseidon2Hash computes Poseidon2(left, right).
func Poseidon2Hash(left, right *Fr256) Fr256 {
	return GetZKContext().Poseidon2HashPair(left, right)
}

// Poseidon2BatchHash computes batch Poseidon2 hashes.
func Poseidon2BatchHash(left, right []Fr256) ([]Fr256, error) {
	return GetZKContext().Poseidon2BatchHashPair(left, right)
}

// MerkleRoot computes the Poseidon2 Merkle root from leaves.
func MerkleRoot(leaves []Fr256) (Fr256, error) {
	return GetZKContext().Poseidon2MerkleRoot(leaves)
}

// MerkleTree builds a complete Poseidon2 Merkle tree.
func MerkleTree(leaves []Fr256) ([]Fr256, error) {
	return GetZKContext().Poseidon2MerkleTree(leaves)
}

// Commitment computes a Poseidon2 commitment.
func Commitment(value, blinding, salt *Fr256) Fr256 {
	return GetZKContext().Poseidon2Commitment(value, blinding, salt)
}

// Nullifier computes a Poseidon2 nullifier.
func Nullifier(key, commitment, index *Fr256) Fr256 {
	return GetZKContext().Poseidon2Nullifier(key, commitment, index)
}
