//go:build cgo

// Package gpu provides GPU-accelerated cryptographic operations via libcrypto.
// This bridges the luxcpp/crypto C++ library to Go, enabling:
// - BLS12-381 signatures for validator consensus
// - ML-DSA post-quantum signatures
// - Threshold cryptography operations
// - Hash functions (SHA3, BLAKE3)
//
// GPU acceleration uses MLX (Metal on macOS, CUDA on Linux, CPU fallback).
package gpu

/*
#cgo darwin CFLAGS: -I/Users/z/work/luxcpp/crypto/include -I/Users/z/work/luxcpp/lattice/include
#cgo darwin LDFLAGS: -L/Users/z/work/luxcpp/crypto/build/lib -Wl,-rpath,/Users/z/work/luxcpp/crypto/build/lib -L/Users/z/work/luxcpp/lattice/build/lib -Wl,-rpath,/Users/z/work/luxcpp/lattice/build/lib -lcrypto -llattice -framework Metal -framework Foundation -lstdc++
#cgo linux CFLAGS: -I/Users/z/work/luxcpp/crypto/include -I/Users/z/work/luxcpp/lattice/include
#cgo linux LDFLAGS: -L/Users/z/work/luxcpp/crypto/build/lib -Wl,-rpath,/Users/z/work/luxcpp/crypto/build/lib -L/Users/z/work/luxcpp/lattice/build/lib -Wl,-rpath,/Users/z/work/luxcpp/lattice/build/lib -lcrypto -llattice -lstdc++ -lm

#include <stdlib.h>
#include "crypto.h"

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
	ErrInvalidKey    = errors.New("invalid key")
	ErrInvalidSig    = errors.New("invalid signature")
	ErrNullPointer   = errors.New("null pointer")
	ErrGPU           = errors.New("GPU error")
	ErrThreshold     = errors.New("threshold error")
	ErrHash          = errors.New("hash error")
	ErrCGORequired   = errors.New("CGO required for GPU acceleration")
)

// Sizes
const (
	BLSSecretKeySize  = 32
	BLSPublicKeySize  = 48
	BLSSignatureSize  = 96
	BLSMessageSize    = 32

	MLDSASecretKeySize  = 4032
	MLDSAPublicKeySize  = 1952
	MLDSASignatureSize  = 3309
)

// Hash types for batch hashing
const (
	HashTypeSHA3_256 = 0
	HashTypeSHA3_512 = 1
	HashTypeBLAKE3   = 2
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
// BLS12-381 Signatures
// =============================================================================

// BLSKeygen generates a BLS secret key.
// If seed is nil, uses system entropy.
func BLSKeygen(seed []byte) ([]byte, error) {
	sk := make([]byte, BLSSecretKeySize)

	var seedPtr *C.uint8_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
	}

	ret := C.bls_keygen((*C.uint8_t)(unsafe.Pointer(&sk[0])), seedPtr)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
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
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return pk, nil
}

// BLSSign signs a message hash with a BLS secret key.
func BLSSign(sk, msg []byte) ([]byte, error) {
	if len(sk) != BLSSecretKeySize {
		return nil, ErrInvalidKey
	}
	if len(msg) != BLSMessageSize {
		return nil, errors.New("message must be 32 bytes")
	}

	sig := make([]byte, BLSSignatureSize)

	ret := C.bls_sign(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return sig, nil
}

// BLSVerify verifies a BLS signature.
// Returns true if valid, false if invalid.
func BLSVerify(sig, pk, msg []byte) bool {
	if len(sig) != BLSSignatureSize || len(pk) != BLSPublicKeySize || len(msg) != BLSMessageSize {
		return false
	}

	return C.bls_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
	) == 1
}

// BLSAggregateSignatures aggregates multiple BLS signatures.
func BLSAggregateSignatures(sigs [][]byte) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// Create C array of pointers and pin them
	sigPtrs := make([]*C.uint8_t, len(sigs))
	for i, sig := range sigs {
		if len(sig) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
		pinner.Pin(&sig[0])
		sigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&sig[0]))
	}
	pinner.Pin(&sigPtrs[0])

	aggSig := make([]byte, BLSSignatureSize)
	pinner.Pin(&aggSig[0])

	ret := C.bls_aggregate_signatures(
		(*C.uint8_t)(unsafe.Pointer(&aggSig[0])),
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		C.uint32_t(len(sigs)),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return aggSig, nil
}

// BLSAggregatePublicKeys aggregates multiple BLS public keys.
func BLSAggregatePublicKeys(pks [][]byte) ([]byte, error) {
	if len(pks) == 0 {
		return nil, errors.New("no public keys to aggregate")
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	pkPtrs := make([]*C.uint8_t, len(pks))
	for i, pk := range pks {
		if len(pk) != BLSPublicKeySize {
			return nil, ErrInvalidKey
		}
		pinner.Pin(&pk[0])
		pkPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&pk[0]))
	}
	pinner.Pin(&pkPtrs[0])

	aggPK := make([]byte, BLSPublicKeySize)
	pinner.Pin(&aggPK[0])

	ret := C.bls_aggregate_public_keys(
		(*C.uint8_t)(unsafe.Pointer(&aggPK[0])),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		C.uint32_t(len(pks)),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return aggPK, nil
}

// BLSVerifyAggregated verifies an aggregated signature against an aggregated public key.
func BLSVerifyAggregated(aggSig, aggPK, msg []byte) bool {
	if len(aggSig) != BLSSignatureSize || len(aggPK) != BLSPublicKeySize || len(msg) != BLSMessageSize {
		return false
	}

	return C.bls_verify_aggregated(
		(*C.uint8_t)(unsafe.Pointer(&aggSig[0])),
		(*C.uint8_t)(unsafe.Pointer(&aggPK[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
	) == 1
}

// BLSBatchVerify verifies multiple BLS signatures in parallel (GPU-accelerated).
// Returns a slice of verification results (true=valid, false=invalid).
func BLSBatchVerify(sigs, pks, msgs [][]byte) ([]bool, error) {
	n := len(sigs)
	if n == 0 {
		return nil, errors.New("no signatures to verify")
	}
	if len(pks) != n || len(msgs) != n {
		return nil, errors.New("mismatched array lengths")
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	sigPtrs := make([]*C.uint8_t, n)
	pkPtrs := make([]*C.uint8_t, n)
	msgPtrs := make([]*C.uint8_t, n)

	for i := 0; i < n; i++ {
		if len(sigs[i]) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
		if len(pks[i]) != BLSPublicKeySize {
			return nil, ErrInvalidKey
		}
		if len(msgs[i]) != BLSMessageSize {
			return nil, errors.New("message must be 32 bytes")
		}
		pinner.Pin(&sigs[i][0])
		pinner.Pin(&pks[i][0])
		pinner.Pin(&msgs[i][0])
		sigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&sigs[i][0]))
		pkPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&pks[i][0]))
		msgPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&msgs[i][0]))
	}
	pinner.Pin(&sigPtrs[0])
	pinner.Pin(&pkPtrs[0])
	pinner.Pin(&msgPtrs[0])

	results := make([]C.int, n)
	pinner.Pin(&results[0])

	ret := C.bls_batch_verify(
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&msgPtrs[0])),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&results[0])),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	boolResults := make([]bool, n)
	for i, r := range results {
		boolResults[i] = r == 1
	}

	return boolResults, nil
}

// =============================================================================
// ML-DSA (Dilithium) Post-Quantum Signatures
// =============================================================================

// MLDSAKeygen generates an ML-DSA key pair.
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
		seedPtr,
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, nil, codeToError(ret)
	}

	return pk, sk, nil
}

// MLDSASign signs a message with ML-DSA.
func MLDSASign(sk, msg []byte) ([]byte, error) {
	if len(sk) != MLDSASecretKeySize {
		return nil, ErrInvalidKey
	}

	sig := make([]byte, MLDSASignatureSize)
	var sigLen C.size_t

	ret := C.mldsa_sign(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		&sigLen,
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return sig[:sigLen], nil
}

// MLDSAVerify verifies an ML-DSA signature.
func MLDSAVerify(sig, msg, pk []byte) bool {
	if len(pk) != MLDSAPublicKeySize {
		return false
	}

	return C.mldsa_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
	) == 1
}

// MLDSABatchVerify verifies multiple ML-DSA signatures in parallel (GPU-accelerated).
func MLDSABatchVerify(sigs, msgs [][]byte, pks [][]byte) ([]bool, error) {
	n := len(sigs)
	if n == 0 {
		return nil, errors.New("no signatures to verify")
	}
	if len(msgs) != n || len(pks) != n {
		return nil, errors.New("mismatched array lengths")
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	sigPtrs := make([]*C.uint8_t, n)
	sigLens := make([]C.size_t, n)
	msgPtrs := make([]*C.uint8_t, n)
	msgLens := make([]C.size_t, n)
	pkPtrs := make([]*C.uint8_t, n)

	for i := 0; i < n; i++ {
		pinner.Pin(&sigs[i][0])
		pinner.Pin(&msgs[i][0])
		sigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&sigs[i][0]))
		sigLens[i] = C.size_t(len(sigs[i]))
		msgPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&msgs[i][0]))
		msgLens[i] = C.size_t(len(msgs[i]))
		if len(pks[i]) != MLDSAPublicKeySize {
			return nil, ErrInvalidKey
		}
		pinner.Pin(&pks[i][0])
		pkPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&pks[i][0]))
	}
	pinner.Pin(&sigPtrs[0])
	pinner.Pin(&sigLens[0])
	pinner.Pin(&msgPtrs[0])
	pinner.Pin(&msgLens[0])
	pinner.Pin(&pkPtrs[0])

	results := make([]C.int, n)
	pinner.Pin(&results[0])

	ret := C.mldsa_batch_verify(
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(*C.size_t)(unsafe.Pointer(&sigLens[0])),
		(**C.uint8_t)(unsafe.Pointer(&msgPtrs[0])),
		(*C.size_t)(unsafe.Pointer(&msgLens[0])),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&results[0])),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	boolResults := make([]bool, n)
	for i, r := range results {
		boolResults[i] = r == 1
	}

	return boolResults, nil
}

// =============================================================================
// Threshold Cryptography
// =============================================================================

// ThresholdContext manages threshold cryptography operations.
type ThresholdContext struct {
	ptr *C.ThresholdContext
	t   uint32
	n   uint32
	mu  sync.RWMutex
}

// NewThresholdContext creates a new threshold context for t-of-n signatures.
func NewThresholdContext(t, n uint32) (*ThresholdContext, error) {
	if t == 0 || n == 0 || t > n {
		return nil, errors.New("invalid threshold parameters")
	}

	ptr := C.threshold_create(C.uint32_t(t), C.uint32_t(n))
	if ptr == nil {
		return nil, ErrThreshold
	}

	return &ThresholdContext{
		ptr: ptr,
		t:   t,
		n:   n,
	}, nil
}

// Close releases the threshold context resources.
func (tc *ThresholdContext) Close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.ptr != nil {
		C.threshold_destroy(tc.ptr)
		tc.ptr = nil
	}
}

// Keygen generates threshold key shares.
// Returns n shares and the combined public key.
func (tc *ThresholdContext) Keygen(seed []byte) (shares [][]byte, pk []byte, err error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.ptr == nil {
		return nil, nil, errors.New("context closed")
	}

	// Allocate share pointers
	sharePtrs := make([]*C.uint8_t, tc.n)
	for i := uint32(0); i < tc.n; i++ {
		sharePtrs[i] = nil
	}

	var shareSize C.size_t
	pk = make([]byte, BLSPublicKeySize)

	var seedPtr *C.uint8_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
	}

	ret := C.threshold_keygen(
		tc.ptr,
		(**C.uint8_t)(unsafe.Pointer(&sharePtrs[0])),
		&shareSize,
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		seedPtr,
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, nil, codeToError(ret)
	}

	// Copy shares to Go slices and free C memory
	shares = make([][]byte, tc.n)
	for i := uint32(0); i < tc.n; i++ {
		if sharePtrs[i] != nil {
			shares[i] = C.GoBytes(unsafe.Pointer(sharePtrs[i]), C.int(shareSize))
			C.free(unsafe.Pointer(sharePtrs[i]))
		}
	}

	return shares, pk, nil
}

// PartialSign creates a partial signature share.
func (tc *ThresholdContext) PartialSign(shareIndex uint32, share, msg []byte) ([]byte, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if tc.ptr == nil {
		return nil, errors.New("context closed")
	}
	if shareIndex >= tc.n {
		return nil, errors.New("invalid share index")
	}
	if len(msg) != BLSMessageSize {
		return nil, errors.New("message must be 32 bytes")
	}

	partialSig := make([]byte, BLSSignatureSize)

	ret := C.threshold_partial_sign(
		tc.ptr,
		(*C.uint8_t)(unsafe.Pointer(&partialSig[0])),
		C.uint32_t(shareIndex),
		(*C.uint8_t)(unsafe.Pointer(&share[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return partialSig, nil
}

// Combine combines partial signatures into a final signature.
// Uses Lagrange interpolation (GPU-accelerated).
func (tc *ThresholdContext) Combine(partialSigs [][]byte, indices []uint32) ([]byte, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if tc.ptr == nil {
		return nil, errors.New("context closed")
	}
	if uint32(len(partialSigs)) < tc.t {
		return nil, errors.New("not enough partial signatures")
	}
	if len(partialSigs) != len(indices) {
		return nil, errors.New("mismatched array lengths")
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	sigPtrs := make([]*C.uint8_t, len(partialSigs))
	for i, sig := range partialSigs {
		if len(sig) != BLSSignatureSize {
			return nil, ErrInvalidSig
		}
		pinner.Pin(&sig[0])
		sigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&sig[0]))
	}
	pinner.Pin(&sigPtrs[0])

	cIndices := make([]C.uint32_t, len(indices))
	for i, idx := range indices {
		cIndices[i] = C.uint32_t(idx)
	}
	pinner.Pin(&cIndices[0])

	sig := make([]byte, BLSSignatureSize)
	pinner.Pin(&sig[0])

	ret := C.threshold_combine(
		tc.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(*C.uint32_t)(unsafe.Pointer(&cIndices[0])),
		C.uint32_t(len(partialSigs)),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return sig, nil
}

// Verify verifies a threshold signature.
func (tc *ThresholdContext) Verify(sig, pk, msg []byte) bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if tc.ptr == nil {
		return false
	}
	if len(sig) != BLSSignatureSize || len(pk) != BLSPublicKeySize || len(msg) != BLSMessageSize {
		return false
	}

	return C.threshold_verify(
		tc.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
	) == 1
}

// =============================================================================
// Hash Functions
// =============================================================================

// SHA3_256 computes SHA3-256 hash.
func SHA3_256(data []byte) []byte {
	out := make([]byte, 32)
	if len(data) == 0 {
		C.crypto_sha3_256((*C.uint8_t)(unsafe.Pointer(&out[0])), nil, 0)
	} else {
		C.crypto_sha3_256(
			(*C.uint8_t)(unsafe.Pointer(&out[0])),
			(*C.uint8_t)(unsafe.Pointer(&data[0])),
			C.size_t(len(data)),
		)
	}
	return out
}

// SHA3_512 computes SHA3-512 hash.
func SHA3_512(data []byte) []byte {
	out := make([]byte, 64)
	if len(data) == 0 {
		C.crypto_sha3_512((*C.uint8_t)(unsafe.Pointer(&out[0])), nil, 0)
	} else {
		C.crypto_sha3_512(
			(*C.uint8_t)(unsafe.Pointer(&out[0])),
			(*C.uint8_t)(unsafe.Pointer(&data[0])),
			C.size_t(len(data)),
		)
	}
	return out
}

// BLAKE3 computes BLAKE3 hash.
func BLAKE3(data []byte) []byte {
	out := make([]byte, 32)
	if len(data) == 0 {
		C.crypto_blake3((*C.uint8_t)(unsafe.Pointer(&out[0])), nil, 0)
	} else {
		C.crypto_blake3(
			(*C.uint8_t)(unsafe.Pointer(&out[0])),
			(*C.uint8_t)(unsafe.Pointer(&data[0])),
			C.size_t(len(data)),
		)
	}
	return out
}

// BatchHash computes multiple hashes in parallel (GPU-accelerated).
func BatchHash(inputs [][]byte, hashType int) ([][]byte, error) {
	n := len(inputs)
	if n == 0 {
		return nil, errors.New("no inputs")
	}

	var outSize int
	switch hashType {
	case HashTypeSHA3_256, HashTypeBLAKE3:
		outSize = 32
	case HashTypeSHA3_512:
		outSize = 64
	default:
		return nil, ErrHash
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// Allocate outputs
	outputs := make([][]byte, n)
	outPtrs := make([]*C.uint8_t, n)
	inPtrs := make([]*C.uint8_t, n)
	lens := make([]C.size_t, n)

	for i := 0; i < n; i++ {
		outputs[i] = make([]byte, outSize)
		pinner.Pin(&outputs[i][0])
		outPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&outputs[i][0]))
		if len(inputs[i]) > 0 {
			pinner.Pin(&inputs[i][0])
			inPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&inputs[i][0]))
		}
		lens[i] = C.size_t(len(inputs[i]))
	}
	pinner.Pin(&outPtrs[0])
	pinner.Pin(&inPtrs[0])
	pinner.Pin(&lens[0])

	ret := C.crypto_batch_hash(
		(**C.uint8_t)(unsafe.Pointer(&outPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&inPtrs[0])),
		(*C.size_t)(unsafe.Pointer(&lens[0])),
		C.uint32_t(n),
		C.int(hashType),
	)
	if ret != C.CRYPTO_SUCCESS {
		return nil, codeToError(ret)
	}

	return outputs, nil
}

// =============================================================================
// Consensus Helpers
// =============================================================================

// ConsensusVerifyBlock verifies a block's signatures using GPU-accelerated batch operations.
func ConsensusVerifyBlock(blsSigs, blsPKs [][]byte, thresholdSig, thresholdPK, blockHash []byte) bool {
	if len(blockHash) != BLSMessageSize {
		return false
	}

	// Pin all Go memory before passing to C
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var blsSigPtrs, blsPKPtrs []*C.uint8_t
	var blsCount C.uint32_t

	if len(blsSigs) > 0 && len(blsPKs) > 0 {
		if len(blsSigs) != len(blsPKs) {
			return false
		}

		blsSigPtrs = make([]*C.uint8_t, len(blsSigs))
		blsPKPtrs = make([]*C.uint8_t, len(blsPKs))

		for i := range blsSigs {
			if len(blsSigs[i]) != BLSSignatureSize || len(blsPKs[i]) != BLSPublicKeySize {
				return false
			}
			pinner.Pin(&blsSigs[i][0])
			pinner.Pin(&blsPKs[i][0])
			blsSigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&blsSigs[i][0]))
			blsPKPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&blsPKs[i][0]))
		}
		blsCount = C.uint32_t(len(blsSigs))
	}

	var threshSigPtr, threshPKPtr *C.uint8_t
	if len(thresholdSig) > 0 && len(thresholdPK) > 0 {
		if len(thresholdSig) != BLSSignatureSize || len(thresholdPK) != BLSPublicKeySize {
			return false
		}
		pinner.Pin(&thresholdSig[0])
		pinner.Pin(&thresholdPK[0])
		threshSigPtr = (*C.uint8_t)(unsafe.Pointer(&thresholdSig[0]))
		threshPKPtr = (*C.uint8_t)(unsafe.Pointer(&thresholdPK[0]))
	}

	pinner.Pin(&blockHash[0])

	var blsSigPtrPtr, blsPKPtrPtr **C.uint8_t
	if len(blsSigPtrs) > 0 {
		pinner.Pin(&blsSigPtrs[0])
		pinner.Pin(&blsPKPtrs[0])
		blsSigPtrPtr = (**C.uint8_t)(unsafe.Pointer(&blsSigPtrs[0]))
		blsPKPtrPtr = (**C.uint8_t)(unsafe.Pointer(&blsPKPtrs[0]))
	}

	return C.consensus_verify_block(
		blsSigPtrPtr,
		blsPKPtrPtr,
		blsCount,
		threshSigPtr,
		threshPKPtr,
		(*C.uint8_t)(unsafe.Pointer(&blockHash[0])),
	) == 1
}

// =============================================================================
// Helpers
// =============================================================================

func codeToError(code C.int) error {
	switch code {
	case C.CRYPTO_SUCCESS:
		return nil
	case C.CRYPTO_ERROR_INVALID_KEY:
		return ErrInvalidKey
	case C.CRYPTO_ERROR_INVALID_SIG:
		return ErrInvalidSig
	case C.CRYPTO_ERROR_NULL_PTR:
		return ErrNullPointer
	case C.CRYPTO_ERROR_GPU:
		return ErrGPU
	case C.CRYPTO_ERROR_THRESHOLD:
		return ErrThreshold
	case C.CRYPTO_ERROR_HASH:
		return ErrHash
	default:
		return errors.New("unknown crypto error")
	}
}
