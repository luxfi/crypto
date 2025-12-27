//go:build darwin && arm64 && cgo && gpu

// Package gpu provides GPU-accelerated ZK operations via Metal.
//
// This file implements CGO bindings to the luxcpp/crypto Metal ZK library.
// Build with: CGO_ENABLED=1 go build -tags "darwin,arm64,cgo"
package gpu

/*
#cgo CFLAGS: -I/Users/z/work/luxcpp/crypto/include
#cgo LDFLAGS: -L/Users/z/work/luxcpp/crypto/build -lluxcrypto -framework Metal -framework Foundation -lc++

#include <lux/crypto/metal_zk.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"sync"
	"unsafe"
)

// =============================================================================
// Metal ZK Context (CGO)
// =============================================================================

// metalContext holds the CGO context for Metal operations.
type metalContext struct {
	ctx     *C.MetalZKContext
	mu      sync.Mutex
	enabled bool
}

var (
	metalCtx     *metalContext
	metalCtxOnce sync.Once
)

// getMetalContext returns the singleton Metal context.
func getMetalContext() *metalContext {
	metalCtxOnce.Do(func() {
		metalCtx = &metalContext{}
		metalCtx.ctx = C.metal_zk_init()
		metalCtx.enabled = metalCtx.ctx != nil
	})
	return metalCtx
}

// MetalAvailable returns true if Metal ZK acceleration is available.
func MetalAvailable() bool {
	return bool(C.metal_zk_available())
}

// =============================================================================
// Fr256 CGO Helpers
// =============================================================================

// toCFr256 converts Fr256 slice to C array pointer.
// Returns the C array and a cleanup function.
func toCFr256Slice(elements []Fr256) (*C.Fr256, func()) {
	if len(elements) == 0 {
		return nil, func() {}
	}
	// Fr256 in Go is [4]uint64, same layout as C Fr256
	return (*C.Fr256)(unsafe.Pointer(&elements[0])), func() {}
}

// allocCFr256 allocates a C array for Fr256 results.
func allocCFr256(count int) []Fr256 {
	return make([]Fr256, count)
}

// =============================================================================
// GPU Poseidon2 Hash Operations
// =============================================================================

// poseidon2HashPairGPU computes batch Poseidon2 hashes on GPU.
func poseidon2HashPairGPU(left, right []Fr256) ([]Fr256, error) {
	ctx := getMetalContext()
	if !ctx.enabled {
		return nil, errors.New("Metal not available")
	}

	n := len(left)
	if n != len(right) || n == 0 {
		return nil, ErrSizeMismatch
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Allocate output
	output := allocCFr256(n)

	// Get C pointers
	outPtr, _ := toCFr256Slice(output)
	leftPtr, _ := toCFr256Slice(left)
	rightPtr, _ := toCFr256Slice(right)

	// Call Metal function
	ret := C.metal_zk_poseidon2_hash_pair(
		ctx.ctx,
		outPtr,
		leftPtr,
		rightPtr,
		C.uint32_t(n),
	)

	if ret != C.METAL_ZK_SUCCESS {
		return nil, metalError(ret)
	}

	return output, nil
}

// poseidon2MerkleLayerGPU computes one Merkle layer on GPU.
func poseidon2MerkleLayerGPU(nodes []Fr256) ([]Fr256, error) {
	ctx := getMetalContext()
	if !ctx.enabled {
		return nil, errors.New("Metal not available")
	}

	n := len(nodes)
	if n == 0 || n%2 != 0 {
		return nil, ErrInvalidInput
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	parentCount := n / 2
	output := allocCFr256(parentCount)

	outPtr, _ := toCFr256Slice(output)
	nodesPtr, _ := toCFr256Slice(nodes)

	ret := C.metal_zk_poseidon2_merkle_layer(
		ctx.ctx,
		outPtr,
		nodesPtr,
		C.uint32_t(n),
	)

	if ret != C.METAL_ZK_SUCCESS {
		return nil, metalError(ret)
	}

	return output, nil
}

// poseidon2MerkleTreeGPU builds a complete Merkle tree on GPU.
func poseidon2MerkleTreeGPU(leaves []Fr256) ([]Fr256, error) {
	ctx := getMetalContext()
	if !ctx.enabled {
		return nil, errors.New("Metal not available")
	}

	n := len(leaves)
	if n == 0 || (n&(n-1)) != 0 {
		return nil, ErrNotPowerOfTwo
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Tree has n-1 internal nodes
	tree := allocCFr256(n - 1)

	treePtr, _ := toCFr256Slice(tree)
	leavesPtr, _ := toCFr256Slice(leaves)

	ret := C.metal_zk_poseidon2_merkle_tree(
		ctx.ctx,
		treePtr,
		leavesPtr,
		C.uint32_t(n),
	)

	if ret != C.METAL_ZK_SUCCESS {
		return nil, metalError(ret)
	}

	return tree, nil
}

// batchCommitmentGPU computes batch commitments on GPU.
func batchCommitmentGPU(values, blindings, salts []Fr256) ([]Fr256, error) {
	ctx := getMetalContext()
	if !ctx.enabled {
		return nil, errors.New("Metal not available")
	}

	n := len(values)
	if n != len(blindings) || n != len(salts) || n == 0 {
		return nil, ErrSizeMismatch
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	output := allocCFr256(n)

	outPtr, _ := toCFr256Slice(output)
	valuesPtr, _ := toCFr256Slice(values)
	blindingsPtr, _ := toCFr256Slice(blindings)
	saltsPtr, _ := toCFr256Slice(salts)

	ret := C.metal_zk_batch_commitment(
		ctx.ctx,
		outPtr,
		valuesPtr,
		blindingsPtr,
		saltsPtr,
		C.uint32_t(n),
	)

	if ret != C.METAL_ZK_SUCCESS {
		return nil, metalError(ret)
	}

	return output, nil
}

// batchNullifierGPU computes batch nullifiers on GPU.
func batchNullifierGPU(keys, commitments, indices []Fr256) ([]Fr256, error) {
	ctx := getMetalContext()
	if !ctx.enabled {
		return nil, errors.New("Metal not available")
	}

	n := len(keys)
	if n != len(commitments) || n != len(indices) || n == 0 {
		return nil, ErrSizeMismatch
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	output := allocCFr256(n)

	outPtr, _ := toCFr256Slice(output)
	keysPtr, _ := toCFr256Slice(keys)
	commitmentsPtr, _ := toCFr256Slice(commitments)
	indicesPtr, _ := toCFr256Slice(indices)

	ret := C.metal_zk_batch_nullifier(
		ctx.ctx,
		outPtr,
		keysPtr,
		commitmentsPtr,
		indicesPtr,
		C.uint32_t(n),
	)

	if ret != C.METAL_ZK_SUCCESS {
		return nil, metalError(ret)
	}

	return output, nil
}

// =============================================================================
// Error Handling
// =============================================================================

func metalError(code C.int) error {
	switch code {
	case C.METAL_ZK_ERROR_NO_DEVICE:
		return errors.New("metal: no device available")
	case C.METAL_ZK_ERROR_NO_SHADER:
		return errors.New("metal: shader not found")
	case C.METAL_ZK_ERROR_ALLOC:
		return errors.New("metal: allocation failed")
	case C.METAL_ZK_ERROR_NULL_PTR:
		return errors.New("metal: null pointer")
	case C.METAL_ZK_ERROR_INVALID:
		return errors.New("metal: invalid argument")
	case C.METAL_ZK_ERROR_SIZE:
		return errors.New("metal: invalid size")
	default:
		return errors.New("metal: unknown error")
	}
}

// =============================================================================
// GPU Hook Registration
// =============================================================================

// init registers Metal GPU hooks when available.
func init() {
	if MetalAvailable() {
		RegisterGPUHooks(&GPUHooks{
			HashPair:        poseidon2HashPairGPU,
			MerkleLayer:     poseidon2MerkleLayerGPU,
			MerkleTree:      poseidon2MerkleTreeGPU,
			BatchCommitment: batchCommitmentGPU,
			BatchNullifier:  batchNullifierGPU,
		})
	}
}
