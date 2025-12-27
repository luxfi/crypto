//go:build cgo && gpu

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
#cgo pkg-config: lux-crypto-only
#cgo darwin,arm64 CFLAGS: -DUSE_METAL=1
#cgo linux CFLAGS: -DUSE_CUDA=1
#cgo LDFLAGS: -lstdc++

#include <lux/crypto/crypto.h>

// Short aliases for Go code readability (hides lux_ prefix)
#define crypto_gpu_available      lux_crypto_gpu_available
#define crypto_get_backend        lux_crypto_get_backend
#define crypto_clear_cache        lux_crypto_clear_cache

// BLS
#define bls_keygen                lux_crypto_bls_keygen
#define bls_sk_to_pk              lux_crypto_bls_sk_to_pk
#define bls_sign                  lux_crypto_bls_sign
#define bls_verify                lux_crypto_bls_verify
#define bls_aggregate_signatures  lux_crypto_bls_aggregate_signatures
#define bls_aggregate_public_keys lux_crypto_bls_aggregate_public_keys
#define bls_verify_aggregated     lux_crypto_bls_verify_aggregated
#define bls_batch_verify          lux_crypto_bls_batch_verify
#define bls_batch_sign            lux_crypto_bls_batch_sign

// ML-DSA
#define mldsa_keygen              lux_crypto_mldsa_keygen
#define mldsa_sign                lux_crypto_mldsa_sign
#define mldsa_verify              lux_crypto_mldsa_verify
#define mldsa_batch_verify        lux_crypto_mldsa_batch_verify

// Threshold
#define threshold_create          lux_crypto_threshold_create
#define threshold_destroy         lux_crypto_threshold_destroy
#define threshold_keygen          lux_crypto_threshold_keygen
#define threshold_partial_sign    lux_crypto_threshold_partial_sign
#define threshold_combine         lux_crypto_threshold_combine
#define threshold_verify          lux_crypto_threshold_verify

// Hashing
#define crypto_sha3_256           lux_crypto_sha3_256
#define crypto_sha3_512           lux_crypto_sha3_512
#define crypto_blake3             lux_crypto_blake3
#define crypto_batch_hash         lux_crypto_batch_hash

// Consensus
#define consensus_verify_block    lux_crypto_consensus_verify_block

// Error codes
#define CRYPTO_SUCCESS            LUX_CRYPTO_SUCCESS
#define CRYPTO_ERROR_INVALID      LUX_CRYPTO_ERROR_INVALID
#define CRYPTO_ERROR_INVALID_KEY  LUX_CRYPTO_ERROR_INVALID_KEY
#define CRYPTO_ERROR_INVALID_SIG  LUX_CRYPTO_ERROR_INVALID_SIG
#define CRYPTO_ERROR_NULL_PTR     LUX_CRYPTO_ERROR_NULL_PTR
#define CRYPTO_ERROR_GPU          LUX_CRYPTO_ERROR_GPU
#define CRYPTO_ERROR_THRESHOLD    LUX_CRYPTO_ERROR_THRESHOLD
#define CRYPTO_ERROR_HASH         LUX_CRYPTO_ERROR_HASH

// Types
#define ThresholdContext          LuxCryptoThresholdContext

*/
import "C"
import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// pinSlices pins all byte slices and returns a pinner and the C pointer array.
// Caller must call pinner.Unpin() when done.
func pinSlices(slices [][]byte) (*runtime.Pinner, []*C.uint8_t) {
	var pinner runtime.Pinner
	cPtrs := make([]*C.uint8_t, len(slices))
	for i, slice := range slices {
		pinner.Pin(&slice[0])
		cPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&slice[0]))
	}
	pinner.Pin(&cPtrs[0])
	return &pinner, cPtrs
}

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
	return bool(C.crypto_gpu_available())
}

// GetBackend returns the name of the active backend: "Metal", "CUDA", or "CPU".
func GetBackend() string {
	return C.GoString(C.crypto_get_backend())
}

// ClearCache clears internal caches.
func ClearCache() {
	C.crypto_clear_cache()
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

	var seedPtr *C.uint8_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
	}

	ret := C.bls_keygen(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		seedPtr)
	if ret != C.CRYPTO_SUCCESS {
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
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return pk, nil
}

// BLSSign creates a BLS signature.
// Note: msg should be a 32-byte hash of the actual message.
func BLSSign(sk, msg []byte) ([]byte, error) {
	if len(sk) != BLSSecretKeySize {
		return nil, ErrInvalidKey
	}
	if len(msg) == 0 {
		return nil, ErrNullPointer
	}

	// Hash message if not already 32 bytes
	var msgHash [32]byte
	if len(msg) == 32 {
		copy(msgHash[:], msg)
	} else {
		// Use SHA3-256 to hash the message
		SHA3_256Into(msgHash[:], msg)
	}

	sig := make([]byte, BLSSignatureSize)
	ret := C.bls_sign(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0])))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return sig, nil
}

// BLSVerify verifies a BLS signature.
// Note: msg should be a 32-byte hash of the actual message.
func BLSVerify(sig, pk, msg []byte) bool {
	if len(sig) != BLSSignatureSize || len(pk) != BLSPublicKeySize || len(msg) == 0 {
		return false
	}

	// Hash message if not already 32 bytes
	var msgHash [32]byte
	if len(msg) == 32 {
		copy(msgHash[:], msg)
	} else {
		SHA3_256Into(msgHash[:], msg)
	}

	return C.bls_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0]))) == 1
}

// BLSAggregateSignatures aggregates multiple BLS signatures using GPU-accelerated BLS aggregation.
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

	// Pin slices for CGO
	pinner, cSigs := pinSlices(sigs)
	defer pinner.Unpin()

	agg := make([]byte, BLSSignatureSize)
	ret := C.bls_aggregate_signatures(
		(*C.uint8_t)(unsafe.Pointer(&agg[0])),
		(**C.uint8_t)(unsafe.Pointer(&cSigs[0])),
		C.uint32_t(len(sigs)))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return agg, nil
}

// BLSAggregatePublicKeys aggregates multiple BLS public keys using GPU-accelerated aggregation.
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

	// Pin slices for CGO
	pinner, cPKs := pinSlices(pks)
	defer pinner.Unpin()

	agg := make([]byte, BLSPublicKeySize)
	ret := C.bls_aggregate_public_keys(
		(*C.uint8_t)(unsafe.Pointer(&agg[0])),
		(**C.uint8_t)(unsafe.Pointer(&cPKs[0])),
		C.uint32_t(len(pks)))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return agg, nil
}

// BLSVerifyAggregated verifies an aggregated BLS signature against an aggregated public key.
func BLSVerifyAggregated(aggSig, aggPK, msg []byte) bool {
	if len(aggSig) != BLSSignatureSize || len(aggPK) != BLSPublicKeySize || len(msg) == 0 {
		return false
	}

	// Hash message if not already 32 bytes
	var msgHash [32]byte
	if len(msg) == 32 {
		copy(msgHash[:], msg)
	} else {
		SHA3_256Into(msgHash[:], msg)
	}

	return C.bls_verify_aggregated(
		(*C.uint8_t)(unsafe.Pointer(&aggSig[0])),
		(*C.uint8_t)(unsafe.Pointer(&aggPK[0])),
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0]))) == 1
}

// BLSBatchVerify verifies multiple BLS signatures in parallel using GPU-accelerated batch verification.
// Messages are hashed in parallel using a worker pool before verification.
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

	// Pin all slices for CGO
	var pinner runtime.Pinner

	cSigs := make([]*C.uint8_t, n)
	cPKs := make([]*C.uint8_t, n)
	cMsgs := make([]*C.uint8_t, n)
	for i := 0; i < n; i++ {
		pinner.Pin(&sigs[i][0])
		pinner.Pin(&pks[i][0])
		pinner.Pin(&msgHashes[i][0])
		cSigs[i] = (*C.uint8_t)(unsafe.Pointer(&sigs[i][0]))
		cPKs[i] = (*C.uint8_t)(unsafe.Pointer(&pks[i][0]))
		cMsgs[i] = (*C.uint8_t)(unsafe.Pointer(&msgHashes[i][0]))
	}
	pinner.Pin(&cSigs[0])
	pinner.Pin(&cPKs[0])
	pinner.Pin(&cMsgs[0])
	defer pinner.Unpin()

	// Use GPU-accelerated batch verification
	cResults := make([]C.int, n)
	ret := C.bls_batch_verify(
		(**C.uint8_t)(unsafe.Pointer(&cSigs[0])),
		(**C.uint8_t)(unsafe.Pointer(&cPKs[0])),
		(**C.uint8_t)(unsafe.Pointer(&cMsgs[0])),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&cResults[0])))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	// Convert results
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = cResults[i] == 1
	}

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

	// Verify all signatures sequentially using single-verification API
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = C.bls_verify(
			(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
			(*C.uint8_t)(unsafe.Pointer(&pks[i][0])),
			(*C.uint8_t)(unsafe.Pointer(&msgHashes[i][0]))) == 1
	}
	return results, nil
}

// BLSBatchSign signs multiple messages with multiple secret keys in parallel.
// It signs N messages with N secret keys, returning N signatures.
// Uses parallel worker pool for signing operations.
func BLSBatchSign(sks, msgs [][]byte) ([][]byte, error) {
	n := len(sks)
	if n != len(msgs) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	// Validate input sizes
	for i := 0; i < n; i++ {
		if len(sks[i]) != BLSSecretKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Hash all messages in parallel
	msgHashes := make([][]byte, n)
	hashMessagesParallel(msgs, msgHashes)

	// Sign all messages in parallel using worker pool
	sigs := make([][]byte, n)
	errs := make([]error, n)

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
				sigs[i] = make([]byte, BLSSignatureSize)
				ret := C.bls_sign(
					(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
					(*C.uint8_t)(unsafe.Pointer(&sks[i][0])),
					(*C.uint8_t)(unsafe.Pointer(&msgHashes[i][0])))
				if ret != C.CRYPTO_SUCCESS {
					errs[i] = codeToError(int(ret))
				}
			}
		}()
	}

	wg.Wait()

	// Check for errors
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return sigs, nil
}

// =============================================================================
// ML-DSA (Post-Quantum) Signatures
// =============================================================================

// MLDSAKeygen generates an ML-DSA key pair using GPU-accelerated lattice operations.
func MLDSAKeygen(seed []byte) (pk, sk []byte, err error) {
	pk = make([]byte, MLDSAPublicKeySize)
	sk = make([]byte, MLDSASecretKeySize)

	var seedPtr *C.uint8_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
	}

	ret := C.mldsa_keygen(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		seedPtr)
	if ret != C.CRYPTO_SUCCESS {
		return nil, nil, codeToError(int(ret))
	}

	return pk, sk, nil
}

// MLDSASign creates an ML-DSA signature using GPU-accelerated NTT.
func MLDSASign(sk, msg []byte) ([]byte, error) {
	if len(sk) != MLDSASecretKeySize {
		return nil, ErrInvalidKey
	}
	if len(msg) == 0 {
		return nil, ErrNullPointer
	}

	sig := make([]byte, MLDSASignatureSize)
	var sigLen C.size_t

	ret := C.mldsa_sign(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		&sigLen,
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return sig[:sigLen], nil
}

// MLDSAVerify verifies an ML-DSA signature using GPU-accelerated NTT.
func MLDSAVerify(sig, msg, pk []byte) bool {
	if len(sig) == 0 || len(pk) != MLDSAPublicKeySize || len(msg) == 0 {
		return false
	}

	return C.mldsa_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&pk[0]))) == 1
}

// MLDSABatchVerify verifies multiple ML-DSA signatures using GPU-accelerated NTT batch operations.
func MLDSABatchVerify(sigs, msgs [][]byte, pks [][]byte) ([]bool, error) {
	n := len(sigs)
	if n != len(msgs) || n != len(pks) {
		return nil, ErrNullPointer
	}
	if n == 0 {
		return nil, ErrNullPointer
	}

	// Validate input sizes before batch operation
	for i := 0; i < n; i++ {
		if len(sigs[i]) == 0 {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != MLDSAPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Pin all slices for CGO
	var pinner runtime.Pinner

	cSigs := make([]*C.uint8_t, n)
	cSigLens := make([]C.size_t, n)
	cMsgs := make([]*C.uint8_t, n)
	cMsgLens := make([]C.size_t, n)
	cPKs := make([]*C.uint8_t, n)

	for i := 0; i < n; i++ {
		pinner.Pin(&sigs[i][0])
		pinner.Pin(&msgs[i][0])
		pinner.Pin(&pks[i][0])
		cSigs[i] = (*C.uint8_t)(unsafe.Pointer(&sigs[i][0]))
		cSigLens[i] = C.size_t(len(sigs[i]))
		cMsgs[i] = (*C.uint8_t)(unsafe.Pointer(&msgs[i][0]))
		cMsgLens[i] = C.size_t(len(msgs[i]))
		cPKs[i] = (*C.uint8_t)(unsafe.Pointer(&pks[i][0]))
	}
	pinner.Pin(&cSigs[0])
	pinner.Pin(&cMsgs[0])
	pinner.Pin(&cPKs[0])
	defer pinner.Unpin()

	// Use GPU-accelerated batch verification
	cResults := make([]C.int, n)
	ret := C.mldsa_batch_verify(
		(**C.uint8_t)(unsafe.Pointer(&cSigs[0])),
		(*C.size_t)(unsafe.Pointer(&cSigLens[0])),
		(**C.uint8_t)(unsafe.Pointer(&cMsgs[0])),
		(*C.size_t)(unsafe.Pointer(&cMsgLens[0])),
		(**C.uint8_t)(unsafe.Pointer(&cPKs[0])),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&cResults[0])))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	// Convert results
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = cResults[i] == 1
	}

	return results, nil
}

// MLDSABatchVerifySequential verifies multiple ML-DSA signatures sequentially.
// Useful for benchmarking to compare sequential vs GPU-accelerated batch performance.
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
		if len(sigs[i]) == 0 {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != MLDSAPublicKeySize {
			return nil, ErrInvalidKey
		}
	}

	// Verify all signatures sequentially using single-verification API
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = C.mldsa_verify(
			(*C.uint8_t)(unsafe.Pointer(&sigs[i][0])),
			C.size_t(len(sigs[i])),
			(*C.uint8_t)(unsafe.Pointer(&msgs[i][0])),
			C.size_t(len(msgs[i])),
			(*C.uint8_t)(unsafe.Pointer(&pks[i][0]))) == 1
	}
	return results, nil
}

// =============================================================================
// Threshold Signatures
// =============================================================================

// ThresholdContext manages threshold signature operations.
type ThresholdContext struct {
	ctx *C.ThresholdContext
	t   uint32
	n   uint32
}

// NewThresholdContext creates a new threshold context with t-of-n scheme.
func NewThresholdContext(t, n uint32) (*ThresholdContext, error) {
	ctx := C.threshold_create(C.uint32_t(t), C.uint32_t(n))
	if ctx == nil {
		return nil, ErrThreshold
	}
	return &ThresholdContext{ctx: ctx, t: t, n: n}, nil
}

// Close releases the threshold context.
func (tc *ThresholdContext) Close() {
	if tc.ctx != nil {
		C.threshold_destroy(tc.ctx)
		tc.ctx = nil
	}
}

// Keygen generates threshold key shares using Shamir Secret Sharing.
// Returns n shares and the combined public key.
func (tc *ThresholdContext) Keygen(seed []byte) (shares [][]byte, pk []byte, err error) {
	if tc.ctx == nil {
		return nil, nil, ErrThreshold
	}

	// Allocate output arrays - use larger buffer for shares (threshold shares may be larger)
	const maxShareSize = 256 // Should be enough for any threshold scheme
	shareSize := C.size_t(0)
	pk = make([]byte, BLSPublicKeySize)

	// Create shares with max size and pin them for CGO
	var pinner runtime.Pinner
	shares = make([][]byte, tc.n)
	cShares := make([]*C.uint8_t, tc.n)
	for i := uint32(0); i < tc.n; i++ {
		shares[i] = make([]byte, maxShareSize)
		pinner.Pin(&shares[i][0])
		cShares[i] = (*C.uint8_t)(unsafe.Pointer(&shares[i][0]))
	}
	pinner.Pin(&cShares[0])
	defer pinner.Unpin()

	var seedPtr *C.uint8_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
	}

	ret := C.threshold_keygen(tc.ctx,
		(**C.uint8_t)(unsafe.Pointer(&cShares[0])),
		&shareSize,
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		seedPtr)
	if ret != C.CRYPTO_SUCCESS {
		return nil, nil, codeToError(int(ret))
	}

	// Resize shares to actual size
	for i := uint32(0); i < tc.n; i++ {
		shares[i] = shares[i][:shareSize]
	}

	return shares, pk, nil
}

// PartialSign creates a partial signature share.
func (tc *ThresholdContext) PartialSign(shareIndex uint32, share, msg []byte) ([]byte, error) {
	if tc.ctx == nil {
		return nil, ErrThreshold
	}
	if len(share) == 0 || len(msg) == 0 {
		return nil, ErrNullPointer
	}

	// Hash message if not already 32 bytes
	var msgHash [32]byte
	if len(msg) == 32 {
		copy(msgHash[:], msg)
	} else {
		SHA3_256Into(msgHash[:], msg)
	}

	partialSig := make([]byte, BLSSignatureSize)
	ret := C.threshold_partial_sign(tc.ctx,
		(*C.uint8_t)(unsafe.Pointer(&partialSig[0])),
		C.uint32_t(shareIndex),
		(*C.uint8_t)(unsafe.Pointer(&share[0])),
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0])))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return partialSig, nil
}

// Combine combines partial signatures into a full signature using Lagrange interpolation.
func (tc *ThresholdContext) Combine(partialSigs [][]byte, indices []uint32) ([]byte, error) {
	if tc.ctx == nil {
		return nil, ErrThreshold
	}
	if len(partialSigs) < int(tc.t) {
		return nil, ErrThreshold
	}
	if len(partialSigs) != len(indices) {
		return nil, ErrNullPointer
	}

	// Pin all slices for CGO
	var pinner runtime.Pinner

	cPartials := make([]*C.uint8_t, len(partialSigs))
	for i, partial := range partialSigs {
		if len(partial) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
		pinner.Pin(&partial[0])
		cPartials[i] = (*C.uint8_t)(unsafe.Pointer(&partial[0]))
	}
	pinner.Pin(&cPartials[0])
	defer pinner.Unpin()

	cIndices := make([]C.uint32_t, len(indices))
	for i, idx := range indices {
		cIndices[i] = C.uint32_t(idx)
	}

	sig := make([]byte, BLSSignatureSize)
	ret := C.threshold_combine(tc.ctx,
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(**C.uint8_t)(unsafe.Pointer(&cPartials[0])),
		(*C.uint32_t)(unsafe.Pointer(&cIndices[0])),
		C.uint32_t(len(partialSigs)))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return sig, nil
}

// Verify verifies a threshold signature.
func (tc *ThresholdContext) Verify(sig, pk, msg []byte) bool {
	if tc.ctx == nil || len(sig) != BLSSignatureSize || len(pk) != BLSPublicKeySize || len(msg) == 0 {
		return false
	}

	// Hash message if not already 32 bytes
	var msgHash [32]byte
	if len(msg) == 32 {
		copy(msgHash[:], msg)
	} else {
		SHA3_256Into(msgHash[:], msg)
	}

	return C.threshold_verify(tc.ctx,
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0]))) == 1
}

// =============================================================================
// Hash Functions
// =============================================================================

// SHA3_256Into computes SHA3-256 hash into a pre-allocated buffer.
func SHA3_256Into(out, data []byte) {
	if len(out) < 32 {
		return
	}
	if len(data) == 0 {
		for i := range out[:32] {
			out[i] = 0
		}
		return
	}
	C.crypto_sha3_256(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
}

// SHA3_256 computes SHA3-256 hash.
func SHA3_256(data []byte) []byte {
	out := make([]byte, 32)
	if len(data) == 0 {
		return out
	}
	C.crypto_sha3_256(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
	return out
}

// SHA3_512 computes SHA3-512 hash.
func SHA3_512(data []byte) []byte {
	out := make([]byte, 64)
	if len(data) == 0 {
		return out
	}
	C.crypto_sha3_512(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
	return out
}

// BLAKE3 computes BLAKE3 hash.
func BLAKE3(data []byte) []byte {
	out := make([]byte, 32)
	if len(data) == 0 {
		return out
	}
	C.crypto_blake3(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
	return out
}

// BatchHash computes multiple hashes in parallel using GPU acceleration.
func BatchHash(inputs [][]byte, hashType int) ([][]byte, error) {
	n := len(inputs)
	if n == 0 {
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

	// Pin all slices for CGO
	var pinner runtime.Pinner

	// Allocate output buffers
	results := make([][]byte, n)
	cOuts := make([]*C.uint8_t, n)
	cIns := make([]*C.uint8_t, n)
	cLens := make([]C.size_t, n)

	for i, input := range inputs {
		results[i] = make([]byte, hashSize)
		pinner.Pin(&results[i][0])
		cOuts[i] = (*C.uint8_t)(unsafe.Pointer(&results[i][0]))
		if len(input) > 0 {
			pinner.Pin(&input[0])
			cIns[i] = (*C.uint8_t)(unsafe.Pointer(&input[0]))
		}
		cLens[i] = C.size_t(len(input))
	}
	pinner.Pin(&cOuts[0])
	pinner.Pin(&cIns[0])
	defer pinner.Unpin()

	// Use GPU-accelerated batch hashing
	ret := C.crypto_batch_hash(
		(**C.uint8_t)(unsafe.Pointer(&cOuts[0])),
		(**C.uint8_t)(unsafe.Pointer(&cIns[0])),
		(*C.size_t)(unsafe.Pointer(&cLens[0])),
		C.uint32_t(n),
		C.int(hashType))
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(int(ret))
	}

	return results, nil
}

// =============================================================================
// Consensus Helper
// =============================================================================

// ConsensusVerifyBlock verifies both BLS and threshold signatures for a block.
// Uses GPU-accelerated consensus verification from the C library.
func ConsensusVerifyBlock(blsSigs, blsPKs [][]byte, thresholdSig, thresholdPK, blockHash []byte) bool {
	if len(blockHash) != 32 {
		return false
	}

	// Pin slices for CGO
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// Create C arrays for BLS signatures and public keys
	var cSigs **C.uint8_t
	var cPKs **C.uint8_t
	blsCount := uint32(0)

	if len(blsSigs) > 0 && len(blsPKs) > 0 && len(blsSigs) == len(blsPKs) {
		blsCount = uint32(len(blsSigs))
		cSigsSlice := make([]*C.uint8_t, blsCount)
		cPKsSlice := make([]*C.uint8_t, blsCount)
		for i := uint32(0); i < blsCount; i++ {
			if len(blsSigs[i]) != BLSSignatureSize || len(blsPKs[i]) != BLSPublicKeySize {
				return false
			}
			pinner.Pin(&blsSigs[i][0])
			pinner.Pin(&blsPKs[i][0])
			cSigsSlice[i] = (*C.uint8_t)(unsafe.Pointer(&blsSigs[i][0]))
			cPKsSlice[i] = (*C.uint8_t)(unsafe.Pointer(&blsPKs[i][0]))
		}
		pinner.Pin(&cSigsSlice[0])
		pinner.Pin(&cPKsSlice[0])
		cSigs = (**C.uint8_t)(unsafe.Pointer(&cSigsSlice[0]))
		cPKs = (**C.uint8_t)(unsafe.Pointer(&cPKsSlice[0]))
	}

	// Handle threshold signature
	var threshSig *C.uint8_t
	var threshPK *C.uint8_t
	if len(thresholdSig) == BLSSignatureSize && len(thresholdPK) == BLSPublicKeySize {
		threshSig = (*C.uint8_t)(unsafe.Pointer(&thresholdSig[0]))
		threshPK = (*C.uint8_t)(unsafe.Pointer(&thresholdPK[0]))
	}

	return C.consensus_verify_block(
		cSigs,
		cPKs,
		C.uint32_t(blsCount),
		threshSig,
		threshPK,
		(*C.uint8_t)(unsafe.Pointer(&blockHash[0]))) == 1
}

// =============================================================================
// Internal Helpers
// =============================================================================

// sha3Into256 computes SHA3-256 into a provided buffer (no size check).
func sha3Into256(out, data []byte) {
	C.crypto_sha3_256(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
}

// sha3Into512 computes SHA3-512 into a provided buffer (no size check).
func sha3Into512(out, data []byte) {
	C.crypto_sha3_512(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
}

// blake3Into computes BLAKE3 into a provided buffer (no size check).
func blake3Into(out, data []byte) {
	C.crypto_blake3(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
}

func codeToError(code int) error {
	switch code {
	case int(C.CRYPTO_SUCCESS):
		return nil
	case int(C.CRYPTO_ERROR_INVALID_KEY):
		return ErrInvalidKey
	case int(C.CRYPTO_ERROR_INVALID_SIG):
		return ErrInvalidSig
	case int(C.CRYPTO_ERROR_NULL_PTR):
		return ErrNullPointer
	case int(C.CRYPTO_ERROR_GPU):
		return ErrGPU
	case int(C.CRYPTO_ERROR_THRESHOLD):
		return ErrThreshold
	case int(C.CRYPTO_ERROR_HASH):
		return ErrHash
	default:
		return ErrGPU
	}
}
