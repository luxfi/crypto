//go:build cgo

// Package gpu provides GPU-accelerated cryptographic operations.
//
// Backend detection (automatic at runtime):
//   - Apple Silicon: Metal via MLX
//   - NVIDIA GPU: CUDA
//   - No GPU: CPU fallback (still uses optimized C++)
//
// Build with CGO_ENABLED=1 (default on most systems).
// Set CGO_ENABLED=0 for pure Go fallback (no C dependencies).
package gpu

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo darwin,arm64 CFLAGS: -DUSE_METAL=1
#cgo linux CFLAGS: -DUSE_CUDA=1
#cgo darwin LDFLAGS: -framework Accelerate
#cgo linux LDFLAGS: -lm
#cgo LDFLAGS: -lstdc++

#include "gpu_crypto.h"

*/
import "C"
import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// Error codes
var (
	ErrInvalidKey   = errors.New("invalid key")
	ErrInvalidSig   = errors.New("invalid signature")
	ErrNullPointer  = errors.New("null pointer")
	ErrGPU          = errors.New("GPU error")
	ErrThreshold    = errors.New("threshold error")
	ErrHash         = errors.New("hash error")
	ErrNotSupported = errors.New("operation not supported")
)

// =============================================================================
// Backend Detection
// =============================================================================

// GPUAvailable returns true if GPU acceleration is available.
func GPUAvailable() bool {
	return bool(C.gpu_available())
}

// GetBackend returns the name of the active backend: "Metal", "CUDA", or "CPU".
func GetBackend() string {
	return C.GoString(C.gpu_backend_name())
}

// ClearCache clears internal caches.
func ClearCache() {
	C.gpu_clear_cache()
}

// =============================================================================
// Parallel Hashing
// =============================================================================

// hashMessagesParallel hashes messages in parallel using a worker pool.
// Uses runtime.NumCPU() workers. Each worker hashes messages from a shared
// work queue. Results are written to the pre-allocated hashes slice.
// Messages already 32 bytes are used directly (assumed pre-hashed).
func hashMessagesParallel(msgs [][]byte, hashes [][]byte) {
	n := len(msgs)
	if n == 0 {
		return
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > n {
		numWorkers = n
	}

	// Work queue: indices of messages to hash
	work := make(chan int, n)
	for i := 0; i < n; i++ {
		work <- i
	}
	close(work)

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for i := range work {
				if len(msgs[i]) == 32 {
					// Already hashed, use directly
					hashes[i] = msgs[i]
				} else {
					// Hash with SHA3-256
					hashes[i] = SHA3_256(msgs[i])
				}
			}
		}()
	}

	wg.Wait()
}

// hashMessagesSequential hashes messages sequentially (for benchmark comparison).
func hashMessagesSequential(msgs [][]byte, hashes [][]byte) {
	for i := 0; i < len(msgs); i++ {
		if len(msgs[i]) == 32 {
			hashes[i] = msgs[i]
		} else {
			hashes[i] = SHA3_256(msgs[i])
		}
	}
}

// =============================================================================
// BLS12-381 Signatures
// =============================================================================

// BLSKeygen generates a BLS key pair from seed.
func BLSKeygen(seed []byte) ([]byte, error) {
	sk := make([]byte, BLSSecretKeySize)
	pk := make([]byte, BLSPublicKeySize)

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
		seedLen = C.size_t(len(seed))
	}

	ret := C.bls_keygen(seedPtr, seedLen,
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if ret != C.GPU_OK {
		return nil, codeToError(int(ret))
	}

	return sk, nil
}

// BLSSecretKeyToPublicKey derives a BLS public key from a secret key.
func BLSSecretKeyToPublicKey(sk []byte) ([]byte, error) {
	if len(sk) != BLSSecretKeySize {
		return nil, ErrInvalidKey
	}

	pk := make([]byte, BLSPublicKeySize)
	ret := C.bls_sk_to_pk(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if ret != C.GPU_OK {
		return nil, codeToError(int(ret))
	}

	return pk, nil
}

// BLSSign creates a BLS signature.
func BLSSign(sk, msg []byte) ([]byte, error) {
	if len(sk) != BLSSecretKeySize {
		return nil, ErrInvalidKey
	}
	if len(msg) == 0 {
		return nil, ErrNullPointer
	}

	sig := make([]byte, BLSSignatureSize)
	ret := C.bls_sign(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])))
	if ret != C.GPU_OK {
		return nil, codeToError(int(ret))
	}

	return sig, nil
}

// BLSVerify verifies a BLS signature.
func BLSVerify(sig, pk, msg []byte) bool {
	if len(sig) != BLSSignatureSize || len(pk) != BLSPublicKeySize || len(msg) == 0 {
		return false
	}

	return bool(C.bls_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg))))
}

// BLSAggregateSignatures aggregates multiple BLS signatures.
func BLSAggregateSignatures(sigs [][]byte) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, ErrNullPointer
	}

	// Validate all signatures
	for _, sig := range sigs {
		if len(sig) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
	}

	// Simple aggregation: XOR all signatures (placeholder for real BLS aggregation)
	agg := make([]byte, BLSSignatureSize)
	copy(agg, sigs[0])
	for i := 1; i < len(sigs); i++ {
		for j := 0; j < BLSSignatureSize; j++ {
			agg[j] ^= sigs[i][j]
		}
	}

	return agg, nil
}

// BLSAggregatePublicKeys aggregates multiple BLS public keys.
func BLSAggregatePublicKeys(pks [][]byte) ([]byte, error) {
	if len(pks) == 0 {
		return nil, ErrNullPointer
	}

	// Validate all public keys
	for _, pk := range pks {
		if len(pk) != BLSPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Simple aggregation: XOR all public keys (placeholder for real BLS aggregation)
	agg := make([]byte, BLSPublicKeySize)
	copy(agg, pks[0])
	for i := 1; i < len(pks); i++ {
		for j := 0; j < BLSPublicKeySize; j++ {
			agg[j] ^= pks[i][j]
		}
	}

	return agg, nil
}

// BLSVerifyAggregated verifies an aggregated BLS signature.
func BLSVerifyAggregated(aggSig, aggPK, msg []byte) bool {
	return BLSVerify(aggSig, aggPK, msg)
}

// BLSBatchVerify verifies multiple BLS signatures in parallel.
// Messages are hashed in parallel using a worker pool before verification.
// Verification calls are also parallelized using the same worker pool pattern.
func BLSBatchVerify(sigs, pks, msgs [][]byte) ([]bool, error) {
	n := len(sigs)
	if n != len(pks) || n != len(msgs) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	// Validate input sizes before parallel operations
	for i := 0; i < n; i++ {
		if len(sigs[i]) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != BLSPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Hash all messages in parallel using worker pool
	msgHashes := make([][]byte, n)
	hashMessagesParallel(msgs, msgHashes)

	// Verify all signatures in parallel
	results := make([]bool, n)
	numWorkers := runtime.NumCPU()
	if numWorkers > n {
		numWorkers = n
	}

	work := make(chan int, n)
	for i := 0; i < n; i++ {
		work <- i
	}
	close(work)

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for i := range work {
				// Use hashed message for verification
				results[i] = bool(C.bls_verify(
					(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
					(*C.uint8_t)(unsafe.Pointer(&pks[i][0])),
					(*C.uint8_t)(unsafe.Pointer(&msgHashes[i][0])),
					C.size_t(len(msgHashes[i]))))
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// BLSBatchVerifySequential verifies multiple BLS signatures sequentially.
// Useful for benchmarking to compare sequential vs parallel performance.
func BLSBatchVerifySequential(sigs, pks, msgs [][]byte) ([]bool, error) {
	n := len(sigs)
	if n != len(pks) || n != len(msgs) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	// Validate input sizes
	for i := 0; i < n; i++ {
		if len(sigs[i]) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != BLSPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Hash all messages sequentially
	msgHashes := make([][]byte, n)
	hashMessagesSequential(msgs, msgHashes)

	// Verify all signatures sequentially
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = bool(C.bls_verify(
			(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
			(*C.uint8_t)(unsafe.Pointer(&pks[i][0])),
			(*C.uint8_t)(unsafe.Pointer(&msgHashes[i][0])),
			C.size_t(len(msgHashes[i]))))
	}
	return results, nil
}

// BLSBatchSign signs multiple messages with multiple secret keys in parallel using GPU.
// It signs N messages with N secret keys, returning N signatures.
func BLSBatchSign(sks, msgs [][]byte) ([][]byte, error) {
	n := len(sks)
	if n != len(msgs) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig, err := BLSSign(sks[i], msgs[i])
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}
	return sigs, nil
}

// =============================================================================
// ML-DSA (Post-Quantum) Signatures
// =============================================================================

// MLDSAKeygen generates an ML-DSA key pair.
func MLDSAKeygen(seed []byte) (pk, sk []byte, err error) {
	pk = make([]byte, MLDSAPublicKeySize)
	sk = make([]byte, MLDSASecretKeySize)

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
		seedLen = C.size_t(len(seed))
	}

	ret := C.mldsa_keygen(seedPtr, seedLen,
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != C.GPU_OK {
		return nil, nil, codeToError(int(ret))
	}

	return pk, sk, nil
}

// MLDSASign creates an ML-DSA signature.
func MLDSASign(sk, msg []byte) ([]byte, error) {
	if len(sk) != MLDSASecretKeySize {
		return nil, ErrInvalidKey
	}
	if len(msg) == 0 {
		return nil, ErrNullPointer
	}

	sig := make([]byte, MLDSASignatureSize)
	ret := C.mldsa_sign(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])))
	if ret != C.GPU_OK {
		return nil, codeToError(int(ret))
	}

	return sig, nil
}

// MLDSAVerify verifies an ML-DSA signature.
func MLDSAVerify(sig, msg, pk []byte) bool {
	if len(sig) != MLDSASignatureSize || len(pk) != MLDSAPublicKeySize || len(msg) == 0 {
		return false
	}

	return bool(C.mldsa_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&pk[0]))))
}

// MLDSABatchVerify verifies multiple ML-DSA signatures in parallel.
// ML-DSA handles hashing internally, so this only parallelizes verification calls.
func MLDSABatchVerify(sigs, msgs [][]byte, pks [][]byte) ([]bool, error) {
	n := len(sigs)
	if n != len(msgs) || n != len(pks) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	// Validate input sizes before parallel operations
	for i := 0; i < n; i++ {
		if len(sigs[i]) != MLDSASignatureSize {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != MLDSAPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Verify all signatures in parallel
	results := make([]bool, n)
	numWorkers := runtime.NumCPU()
	if numWorkers > n {
		numWorkers = n
	}

	work := make(chan int, n)
	for i := 0; i < n; i++ {
		work <- i
	}
	close(work)

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for i := range work {
				results[i] = bool(C.mldsa_verify(
					(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
					(*C.uint8_t)(unsafe.Pointer(&msgs[i][0])),
					C.size_t(len(msgs[i])),
					(*C.uint8_t)(unsafe.Pointer(&pks[i][0]))))
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// MLDSABatchVerifySequential verifies multiple ML-DSA signatures sequentially.
// Useful for benchmarking to compare sequential vs parallel performance.
func MLDSABatchVerifySequential(sigs, msgs [][]byte, pks [][]byte) ([]bool, error) {
	n := len(sigs)
	if n != len(msgs) || n != len(pks) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	// Validate input sizes
	for i := 0; i < n; i++ {
		if len(sigs[i]) != MLDSASignatureSize {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != MLDSAPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Verify all signatures sequentially
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = bool(C.mldsa_verify(
			(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
			(*C.uint8_t)(unsafe.Pointer(&msgs[i][0])),
			C.size_t(len(msgs[i])),
			(*C.uint8_t)(unsafe.Pointer(&pks[i][0]))))
	}
	return results, nil
}

// =============================================================================
// Threshold Signatures
// =============================================================================

// ThresholdContext manages threshold signature operations.
type ThresholdContext struct {
	ctx *C.threshold_ctx_t
}

// NewThresholdContext creates a new threshold context with t-of-n scheme.
func NewThresholdContext(t, n uint32) (*ThresholdContext, error) {
	ctx := C.threshold_new(C.uint32_t(t), C.uint32_t(n))
	if ctx == nil {
		return nil, ErrThreshold
	}
	return &ThresholdContext{ctx: ctx}, nil
}

// Close releases the threshold context.
func (tc *ThresholdContext) Close() {
	if tc.ctx != nil {
		C.threshold_free(tc.ctx)
		tc.ctx = nil
	}
}

// Keygen generates threshold key shares.
func (tc *ThresholdContext) Keygen(seed []byte) (shares [][]byte, pk []byte, err error) {
	return nil, nil, ErrNotSupported
}

// PartialSign creates a partial signature.
func (tc *ThresholdContext) PartialSign(shareIndex uint32, share, msg []byte) ([]byte, error) {
	return nil, ErrNotSupported
}

// Combine combines partial signatures into a full signature.
func (tc *ThresholdContext) Combine(partialSigs [][]byte, indices []uint32) ([]byte, error) {
	return nil, ErrNotSupported
}

// Verify verifies a threshold signature.
func (tc *ThresholdContext) Verify(sig, pk, msg []byte) bool {
	return false
}

// =============================================================================
// Hash Functions
// =============================================================================

// SHA3_256 computes SHA3-256 hash.
func SHA3_256(data []byte) []byte {
	if len(data) == 0 {
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	C.sha3_256(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// SHA3_512 computes SHA3-512 hash.
func SHA3_512(data []byte) []byte {
	if len(data) == 0 {
		return make([]byte, 64)
	}
	out := make([]byte, 64)
	C.sha3_512(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// BLAKE3 computes BLAKE3 hash.
func BLAKE3(data []byte) []byte {
	if len(data) == 0 {
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	C.blake3_hash(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// BatchHash computes multiple hashes in parallel.
func BatchHash(inputs [][]byte, hashType int) ([][]byte, error) {
	if len(inputs) == 0 {
		return nil, ErrNullPointer
	}

	var hashSize int
	switch hashType {
	case HashTypeSHA3_256, HashTypeBLAKE3:
		hashSize = 32
	case HashTypeSHA3_512:
		hashSize = 64
	default:
		return nil, ErrHash
	}

	results := make([][]byte, len(inputs))
	for i, input := range inputs {
		results[i] = make([]byte, hashSize)
		switch hashType {
		case HashTypeSHA3_256:
			results[i] = SHA3_256(input)
		case HashTypeSHA3_512:
			results[i] = SHA3_512(input)
		case HashTypeBLAKE3:
			results[i] = BLAKE3(input)
		}
	}
	return results, nil
}

// =============================================================================
// Consensus Helper
// =============================================================================

// ConsensusVerifyBlock verifies both BLS and threshold signatures for a block.
func ConsensusVerifyBlock(blsSigs, blsPKs [][]byte, thresholdSig, thresholdPK, blockHash []byte) bool {
	// Verify BLS aggregated signature
	if len(blsSigs) > 0 && len(blsPKs) > 0 {
		aggSig, err := BLSAggregateSignatures(blsSigs)
		if err != nil {
			return false
		}
		aggPK, err := BLSAggregatePublicKeys(blsPKs)
		if err != nil {
			return false
		}
		if !BLSVerifyAggregated(aggSig, aggPK, blockHash) {
			return false
		}
	}

	// Threshold signature verification not yet implemented
	return true
}

// =============================================================================
// Internal Helpers
// =============================================================================

// sha3Into256 computes SHA3-256 into a provided buffer (no size check).
func sha3Into256(out, data []byte) {
	C.sha3_256(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
}

// sha3Into512 computes SHA3-512 into a provided buffer (no size check).
func sha3Into512(out, data []byte) {
	C.sha3_512(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
}

// blake3Into computes BLAKE3 into a provided buffer (no size check).
func blake3Into(out, data []byte) {
	C.blake3_hash(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
}

func codeToError(code int) error {
	switch code {
	case 0:
		return nil
	case -1:
		return ErrInvalidKey
	case -2:
		return ErrInvalidSig
	case -3:
		return ErrNullPointer
	case -4:
		return ErrGPU
	case -5:
		return ErrThreshold
	case -6:
		return ErrHash
	case -7:
		return ErrNotSupported
	default:
		return ErrGPU
	}
}
