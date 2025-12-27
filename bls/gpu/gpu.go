// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && metal && darwin

// Package gpu provides GPU-accelerated BLS12-381 operations via Metal.
// This package links to luxcpp/crypto for hardware acceleration.
// The C++ library handles automatic fallback to CPU when GPU is unavailable.
package gpu

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../luxcpp/crypto/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_bls.h"
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/luxfi/crypto/bls"
)

// Thresholds for GPU batch operations
const (
	BatchVerifyThreshold   = 64  // Min signatures for GPU batch verify
	BatchAggregateThreshold = 128 // Min items for GPU aggregation
)

var (
	ctx      *C.MetalBLSContext
	ctxReady bool
)

// initContext lazily initializes the Metal BLS context.
func initContext() error {
	if ctxReady {
		return nil
	}
	ctx = C.metal_bls_init()
	if ctx == nil {
		return errors.New("Metal BLS initialization failed")
	}
	ctxReady = true
	return nil
}

// Available returns true if Metal GPU acceleration is available for BLS.
func Available() bool {
	return bool(C.metal_bls_available())
}

// BatchVerify verifies multiple BLS signatures using GPU acceleration.
// Returns a slice of booleans indicating validity of each signature.
// Falls back to sequential verification if GPU is unavailable or count < threshold.
func BatchVerify(pks []*bls.PublicKey, sigs []*bls.Signature, msgs [][]byte) ([]bool, error) {
	n := len(pks)
	if n == 0 || n != len(sigs) || n != len(msgs) {
		return nil, errors.New("mismatched input lengths")
	}

	results := make([]bool, n)

	// Fall back to sequential for small batches or no GPU
	if n < BatchVerifyThreshold || !Available() {
		for i := 0; i < n; i++ {
			results[i] = bls.Verify(pks[i], sigs[i], msgs[i])
		}
		return results, nil
	}

	if err := initContext(); err != nil {
		// Fall back to sequential on init error
		for i := 0; i < n; i++ {
			results[i] = bls.Verify(pks[i], sigs[i], msgs[i])
		}
		return results, nil
	}

	// Prepare C arrays
	sigPtrs := make([]*C.uint8_t, n)
	pkPtrs := make([]*C.uint8_t, n)
	msgPtrs := make([]*C.uint8_t, n)
	intResults := make([]C.int, n)

	// Serialize keys and signatures
	sigBytes := make([][]byte, n)
	pkBytes := make([][]byte, n)
	msgCopies := make([][]byte, n)

	for i := 0; i < n; i++ {
		if pks[i] == nil || sigs[i] == nil {
			return nil, errors.New("nil public key or signature")
		}
		sigBytes[i] = bls.SignatureToBytes(sigs[i])
		pkBytes[i] = bls.PublicKeyToCompressedBytes(pks[i])
		msgCopies[i] = msgs[i] // Keep reference

		if len(sigBytes[i]) == 0 || len(pkBytes[i]) == 0 {
			return nil, errors.New("failed to serialize key or signature")
		}

		sigPtrs[i] = (*C.uint8_t)(&sigBytes[i][0])
		pkPtrs[i] = (*C.uint8_t)(&pkBytes[i][0])
		if len(msgCopies[i]) > 0 {
			msgPtrs[i] = (*C.uint8_t)(&msgCopies[i][0])
		}
	}

	ret := C.metal_bls_batch_verify(
		ctx,
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&msgPtrs[0])),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&intResults[0])),
	)

	if ret < 0 {
		// GPU error, fall back to sequential
		for i := 0; i < n; i++ {
			results[i] = bls.Verify(pks[i], sigs[i], msgs[i])
		}
		return results, nil
	}

	// Convert results
	for i := 0; i < n; i++ {
		results[i] = intResults[i] != 0
	}

	return results, nil
}

// AggregateSignatures aggregates signatures using GPU acceleration.
// Falls back to CPU aggregation if GPU is unavailable or count < threshold.
func AggregateSignatures(sigs []*bls.Signature) (*bls.Signature, error) {
	n := len(sigs)
	if n == 0 {
		return nil, bls.ErrNoSignatures
	}

	// Fall back to CPU for small batches
	if n < BatchAggregateThreshold || !Available() {
		return bls.AggregateSignatures(sigs)
	}

	if err := initContext(); err != nil {
		return bls.AggregateSignatures(sigs)
	}

	// Prepare signature array
	sigPtrs := make([]*C.uint8_t, n)
	sigBytes := make([][]byte, n)

	for i := 0; i < n; i++ {
		if sigs[i] == nil {
			return nil, bls.ErrFailedSignatureAggregation
		}
		sigBytes[i] = bls.SignatureToBytes(sigs[i])
		if len(sigBytes[i]) == 0 {
			return nil, bls.ErrFailedSignatureAggregation
		}
		sigPtrs[i] = (*C.uint8_t)(&sigBytes[i][0])
	}

	// Allocate output
	aggSig := make([]byte, bls.SignatureLen)

	ret := C.metal_bls_aggregate_sigs(
		ctx,
		(*C.uint8_t)(&aggSig[0]),
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		C.uint32_t(n),
	)

	if ret != C.METAL_BLS_SUCCESS {
		// Fall back to CPU
		return bls.AggregateSignatures(sigs)
	}

	return bls.SignatureFromBytes(aggSig)
}

// AggregatePublicKeys aggregates public keys using GPU acceleration.
// Falls back to CPU aggregation if GPU is unavailable or count < threshold.
func AggregatePublicKeys(pks []*bls.PublicKey) (*bls.PublicKey, error) {
	n := len(pks)
	if n == 0 {
		return nil, bls.ErrNoPublicKeys
	}

	// Fall back to CPU for small batches
	if n < BatchAggregateThreshold || !Available() {
		return bls.AggregatePublicKeys(pks)
	}

	if err := initContext(); err != nil {
		return bls.AggregatePublicKeys(pks)
	}

	// Prepare public key array
	pkPtrs := make([]*C.uint8_t, n)
	pkBytes := make([][]byte, n)

	for i := 0; i < n; i++ {
		if pks[i] == nil {
			return nil, bls.ErrInvalidPublicKey
		}
		pkBytes[i] = bls.PublicKeyToCompressedBytes(pks[i])
		if len(pkBytes[i]) == 0 {
			return nil, bls.ErrFailedPublicKeyAggregation
		}
		pkPtrs[i] = (*C.uint8_t)(&pkBytes[i][0])
	}

	// Allocate output
	aggPk := make([]byte, bls.PublicKeyLen)

	ret := C.metal_bls_aggregate_pks(
		ctx,
		(*C.uint8_t)(&aggPk[0]),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		C.uint32_t(n),
	)

	if ret != C.METAL_BLS_SUCCESS {
		// Fall back to CPU
		return bls.AggregatePublicKeys(pks)
	}

	return bls.PublicKeyFromCompressedBytes(aggPk)
}

// MultiScalarMul performs multi-scalar multiplication on GPU.
// result = sum_i (scalars[i] * points[i])
// This is useful for batch verification and commitment schemes.
func MultiScalarMul(points []*bls.PublicKey, scalars [][]byte) (*bls.PublicKey, error) {
	n := len(points)
	if n == 0 || n != len(scalars) {
		return nil, errors.New("mismatched input lengths")
	}

	// Validate scalar lengths (256-bit = 32 bytes)
	for i := 0; i < n; i++ {
		if len(scalars[i]) != 32 {
			return nil, errors.New("scalars must be 32 bytes")
		}
	}

	if err := initContext(); err != nil {
		return nil, err
	}

	// Serialize points to G1Affine format
	type g1Affine struct {
		x    [48]byte
		y    [48]byte
		_pad [8]byte
	}
	pointsArr := make([]g1Affine, n)

	for i := 0; i < n; i++ {
		if points[i] == nil {
			return nil, errors.New("nil point")
		}
		pkBytes := bls.PublicKeyToUncompressedBytes(points[i])
		if len(pkBytes) < 96 {
			return nil, errors.New("invalid point serialization")
		}
		copy(pointsArr[i].x[:], pkBytes[:48])
		copy(pointsArr[i].y[:], pkBytes[48:96])
	}

	// Flatten scalars to limbs (4 x 64-bit per scalar)
	scalarLimbs := make([]uint64, n*4)
	for i := 0; i < n; i++ {
		for j := 0; j < 4; j++ {
			scalarLimbs[i*4+j] = 0
			for k := 0; k < 8; k++ {
				scalarLimbs[i*4+j] |= uint64(scalars[i][j*8+k]) << (k * 8)
			}
		}
	}

	// Allocate result
	type g1Proj struct {
		x [48]byte
		y [48]byte
		z [48]byte
	}
	var result g1Proj

	ret := C.metal_bls_msm(
		ctx,
		(*C.G1Projective)(unsafe.Pointer(&result)),
		(*C.G1Affine)(unsafe.Pointer(&pointsArr[0])),
		(*C.uint64_t)(unsafe.Pointer(&scalarLimbs[0])),
		C.uint32_t(n),
	)

	if ret != C.METAL_BLS_SUCCESS {
		return nil, errors.New("MSM failed")
	}

	// Convert projective result back to compressed public key
	resultBytes := make([]byte, 144)
	copy(resultBytes[:48], result.x[:])
	copy(resultBytes[48:96], result.y[:])
	copy(resultBytes[96:], result.z[:])

	// Convert to affine and compress (simplified - in practice need proper conversion)
	// For now, return nil as this requires more complex coordinate conversion
	return nil, errors.New("MSM result conversion not yet implemented")
}

// Destroy releases the Metal BLS context.
// Should be called when done with GPU BLS operations.
func Destroy() {
	if ctxReady && ctx != nil {
		C.metal_bls_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}
