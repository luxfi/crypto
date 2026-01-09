// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// Package gpu provides GPU-accelerated Verkle tree operations via Metal.
// Links to luxcpp/crypto for hardware acceleration on Apple Silicon.
package gpu

/*
#cgo CFLAGS: -I/Users/z/work/luxcpp/crypto/include
#cgo darwin LDFLAGS: -L/Users/z/work/luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation
#cgo linux LDFLAGS: -L/Users/z/work/luxcpp/crypto/build-local -lluxcrypto

#include <stdint.h>
#include <stdbool.h>
#include "lux/crypto/metal_ipa.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"sync"
	"unsafe"

	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/ethereum/go-verkle"
)

// GPU acceleration thresholds
const (
	// MinPolyDegreeGPU is the minimum polynomial degree for GPU acceleration
	MinPolyDegreeGPU = 4

	// BatchCommitThreshold is minimum batch size for GPU batch commits
	BatchCommitThreshold = 8
)

var (
	gpuCtx     *C.MetalIPAContext
	gpuCtxOnce sync.Once
	gpuCtxErr  error
	gpuCtxMu   sync.Mutex
)

// initGPU initializes the Metal IPA context for GPU acceleration.
func initGPU() error {
	gpuCtxOnce.Do(func() {
		gpuCtx = C.metal_ipa_init()
		if gpuCtx == nil {
			gpuCtxErr = errors.New("failed to initialize Metal IPA context")
		}
	})
	return gpuCtxErr
}

// Available returns true if GPU acceleration is available.
func Available() bool {
	return bool(C.metal_ipa_available())
}

// bytesToScalar converts 32-byte big-endian to C.BanderwagonScalar (4 x uint64 limbs, little-endian).
func bytesToScalar(b []byte) C.BanderwagonScalar {
	var s C.BanderwagonScalar
	// Convert big-endian bytes to little-endian limbs
	s.limbs[0] = C.uint64_t(binary.BigEndian.Uint64(b[24:32]))
	s.limbs[1] = C.uint64_t(binary.BigEndian.Uint64(b[16:24]))
	s.limbs[2] = C.uint64_t(binary.BigEndian.Uint64(b[8:16]))
	s.limbs[3] = C.uint64_t(binary.BigEndian.Uint64(b[0:8]))
	return s
}

// pointToAffine converts verkle.Point to C.BanderwagonAffine using serialization.
func pointToAffine(p *verkle.Point) C.BanderwagonAffine {
	var affine C.BanderwagonAffine
	bytes := p.Bytes()
	C.metal_ipa_point_deserialize(&affine, (*C.uint8_t)(unsafe.Pointer(&bytes[0])))
	return affine
}

// affineToPoint converts C.BanderwagonAffine to verkle.Point using serialization.
func affineToPoint(affine *C.BanderwagonAffine) (*verkle.Point, error) {
	var bytes [32]byte
	C.metal_ipa_point_serialize((*C.uint8_t)(unsafe.Pointer(&bytes[0])), affine)
	point := new(verkle.Point)
	if err := point.SetBytes(bytes[:]); err != nil {
		return nil, err
	}
	return point, nil
}

// CommitToPoly performs polynomial commitment using GPU acceleration.
// Falls back to CPU if GPU is unavailable or for small polynomials.
func CommitToPoly(poly []fr.Element) (*verkle.Point, error) {
	n := len(poly)
	if n == 0 {
		return nil, errors.New("empty polynomial")
	}

	// Use CPU for small polynomials
	if n < MinPolyDegreeGPU || !Available() {
		cfg := verkle.GetConfig()
		return cfg.CommitToPoly(poly, 0), nil
	}

	if err := initGPU(); err != nil {
		cfg := verkle.GetConfig()
		return cfg.CommitToPoly(poly, 0), nil
	}

	gpuCtxMu.Lock()
	defer gpuCtxMu.Unlock()

	// Convert scalars to C format
	cScalars := make([]C.BanderwagonScalar, n)
	for i := 0; i < n; i++ {
		bytes := poly[i].Bytes()
		cScalars[i] = bytesToScalar(bytes[:])
	}

	// Perform GPU commitment (no blinding for deterministic commit)
	var cResult C.BanderwagonAffine

	ret := C.metal_ipa_pedersen_commit(
		gpuCtx,
		&cResult,
		(*C.BanderwagonScalar)(unsafe.Pointer(&cScalars[0])),
		nil, // No blinding
		C.uint32_t(n),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to CPU
		cfg := verkle.GetConfig()
		return cfg.CommitToPoly(poly, 0), nil
	}

	return affineToPoint(&cResult)
}

// BatchCommitToPoly performs batch polynomial commitments using GPU.
// Much more efficient than sequential commits for multiple polynomials.
func BatchCommitToPoly(polys [][]fr.Element) ([]*verkle.Point, error) {
	n := len(polys)
	if n == 0 {
		return nil, errors.New("empty polynomial batch")
	}

	// Use sequential CPU for small batches
	if n < BatchCommitThreshold || !Available() {
		results := make([]*verkle.Point, n)
		cfg := verkle.GetConfig()
		for i, poly := range polys {
			results[i] = cfg.CommitToPoly(poly, 0)
		}
		return results, nil
	}

	if err := initGPU(); err != nil {
		results := make([]*verkle.Point, n)
		cfg := verkle.GetConfig()
		for i, poly := range polys {
			results[i] = cfg.CommitToPoly(poly, 0)
		}
		return results, nil
	}

	gpuCtxMu.Lock()
	defer gpuCtxMu.Unlock()

	// Check if all polys have same size (required for batch API)
	vectorSize := len(polys[0])
	for i := 1; i < n; i++ {
		if len(polys[i]) != vectorSize {
			// Fall back to sequential if sizes differ
			results := make([]*verkle.Point, n)
			cfg := verkle.GetConfig()
			for j, poly := range polys {
				results[j] = cfg.CommitToPoly(poly, 0)
			}
			return results, nil
		}
	}

	// Flatten all scalars
	allScalars := make([]C.BanderwagonScalar, n*vectorSize)
	for i, poly := range polys {
		for j, s := range poly {
			bytes := s.Bytes()
			allScalars[i*vectorSize+j] = bytesToScalar(bytes[:])
		}
	}

	// Allocate results
	cResults := make([]C.BanderwagonAffine, n)

	ret := C.metal_ipa_batch_pedersen_commit(
		gpuCtx,
		(*C.BanderwagonAffine)(unsafe.Pointer(&cResults[0])),
		(*C.BanderwagonScalar)(unsafe.Pointer(&allScalars[0])),
		nil, // No blindings
		C.uint32_t(n),
		C.uint32_t(vectorSize),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to CPU
		results := make([]*verkle.Point, n)
		cfg := verkle.GetConfig()
		for i, poly := range polys {
			results[i] = cfg.CommitToPoly(poly, 0)
		}
		return results, nil
	}

	// Convert results
	results := make([]*verkle.Point, n)
	for i := 0; i < n; i++ {
		point, err := affineToPoint(&cResults[i])
		if err != nil {
			// Fall back to CPU for this one
			cfg := verkle.GetConfig()
			results[i] = cfg.CommitToPoly(polys[i], 0)
		} else {
			results[i] = point
		}
	}

	return results, nil
}

// VerkleCommitNode computes a Verkle tree internal node commitment.
// Uses width-256 commitment optimized for Verkle trees.
func VerkleCommitNode(children []*verkle.Point, stem []byte) (*verkle.Point, error) {
	if len(children) != 256 {
		return nil, errors.New("Verkle node requires exactly 256 children")
	}

	if !Available() {
		// Fall back to CPU using verkle config
		cfg := verkle.GetConfig()
		scalars := make([]fr.Element, 256)
		points := make([]verkle.Point, 256)
		for i := 0; i < 256; i++ {
			scalars[i].SetOne()
			if children[i] != nil {
				points[i] = *children[i]
			}
		}
		result := cfg.CommitToPoly(scalars, 0)
		return result, nil
	}

	if err := initGPU(); err != nil {
		cfg := verkle.GetConfig()
		scalars := make([]fr.Element, 256)
		for i := 0; i < 256; i++ {
			scalars[i].SetOne()
		}
		result := cfg.CommitToPoly(scalars, 0)
		return result, nil
	}

	gpuCtxMu.Lock()
	defer gpuCtxMu.Unlock()

	// Convert children to C format
	cChildren := make([]C.BanderwagonAffine, 256)
	for i := 0; i < 256; i++ {
		if children[i] != nil {
			cChildren[i] = pointToAffine(children[i])
		}
		// Zero-initialized for nil children
	}

	// Prepare stem (pad to 32 bytes if needed)
	var stemBytes [32]byte
	if len(stem) > 0 {
		copy(stemBytes[:], stem)
	}

	var cResult C.BanderwagonAffine

	ret := C.metal_verkle_commit_node(
		gpuCtx,
		&cResult,
		(*C.BanderwagonAffine)(unsafe.Pointer(&cChildren[0])),
		(*C.uint8_t)(unsafe.Pointer(&stemBytes[0])),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to CPU
		cfg := verkle.GetConfig()
		scalars := make([]fr.Element, 256)
		for i := 0; i < 256; i++ {
			scalars[i].SetOne()
		}
		result := cfg.CommitToPoly(scalars, 0)
		return result, nil
	}

	return affineToPoint(&cResult)
}

// Destroy releases the Metal IPA context.
func Destroy() {
	gpuCtxMu.Lock()
	defer gpuCtxMu.Unlock()

	if gpuCtx != nil {
		C.metal_ipa_destroy(gpuCtx)
		gpuCtx = nil
	}
}
