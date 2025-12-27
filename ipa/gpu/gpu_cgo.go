// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// Package gpu provides GPU-accelerated IPA/Verkle operations via Metal.
// This package links to luxcpp/crypto for hardware acceleration.
// Used for Verkle witness generation and verification.
package gpu

/*
#cgo pkg-config: lux-crypto-only
#cgo darwin LDFLAGS: -framework Metal -framework Foundation
#cgo linux LDFLAGS: 

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_ipa.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
)

// Thresholds for GPU batch operations
const (
	MSMThreshold       = 64 // Min points for GPU MSM
	PedersenThreshold  = 32 // Min values for GPU Pedersen commit
	IPAVerifyThreshold = 16 // Min proofs for GPU IPA verify
)

var (
	ctx      *C.MetalIPAContext
	ctxReady bool
)

// initContext lazily initializes the Metal IPA context.
func initContext() error {
	if ctxReady {
		return nil
	}
	ctx = C.metal_ipa_init()
	if ctx == nil {
		return errors.New("Metal IPA initialization failed")
	}
	ctxReady = true
	return nil
}

// Available returns true if Metal GPU acceleration is available for IPA.
func Available() bool {
	return bool(C.metal_ipa_available())
}

// bytesToScalar converts 32-byte big-endian to C.BanderwagonScalar (4 x uint64 limbs, little-endian).
func bytesToScalar(b []byte) C.BanderwagonScalar {
	var s C.BanderwagonScalar
	// Convert big-endian bytes to little-endian limbs
	// b[0:8] -> limbs[3], b[8:16] -> limbs[2], b[16:24] -> limbs[1], b[24:32] -> limbs[0]
	s.limbs[0] = C.uint64_t(binary.BigEndian.Uint64(b[24:32]))
	s.limbs[1] = C.uint64_t(binary.BigEndian.Uint64(b[16:24]))
	s.limbs[2] = C.uint64_t(binary.BigEndian.Uint64(b[8:16]))
	s.limbs[3] = C.uint64_t(binary.BigEndian.Uint64(b[0:8]))
	return s
}

// pointToAffine converts banderwagon.Element to C.BanderwagonAffine using serialization.
func pointToAffine(p *banderwagon.Element) C.BanderwagonAffine {
	var affine C.BanderwagonAffine
	bytes := p.Bytes()
	// Use deserialize to get proper affine coordinates
	C.metal_ipa_point_deserialize(&affine, (*C.uint8_t)(unsafe.Pointer(&bytes[0])))
	return affine
}

// affineToPoint converts C.BanderwagonAffine to banderwagon.Element using serialization.
func affineToPoint(affine *C.BanderwagonAffine) (*banderwagon.Element, error) {
	var bytes [32]byte
	C.metal_ipa_point_serialize((*C.uint8_t)(unsafe.Pointer(&bytes[0])), affine)
	var result banderwagon.Element
	if err := result.SetBytes(bytes[:]); err != nil {
		return nil, err
	}
	return &result, nil
}

// MSM performs multi-scalar multiplication on Banderwagon points using GPU.
// result = sum_i (scalars[i] * points[i])
func MSM(points []banderwagon.Element, scalars []fr.Element) (*banderwagon.Element, error) {
	n := len(points)
	if n == 0 || n != len(scalars) {
		return nil, errors.New("mismatched input lengths")
	}

	// Fall back to CPU for small batches
	if n < MSMThreshold || !Available() {
		var result banderwagon.Element
		_, err := result.MultiExp(points, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	if err := initContext(); err != nil {
		var result banderwagon.Element
		_, err := result.MultiExp(points, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	// Convert scalars to C format
	cScalars := make([]C.BanderwagonScalar, n)
	for i := 0; i < n; i++ {
		bytes := scalars[i].Bytes()
		cScalars[i] = bytesToScalar(bytes[:])
	}

	// Convert points to C format
	cPoints := make([]C.BanderwagonAffine, n)
	for i := 0; i < n; i++ {
		cPoints[i] = pointToAffine(&points[i])
	}

	// Allocate result (API uses BanderwagonAffine for result)
	var cResult C.BanderwagonAffine

	ret := C.metal_ipa_msm(
		ctx,
		&cResult,
		(*C.BanderwagonScalar)(unsafe.Pointer(&cScalars[0])),
		(*C.BanderwagonAffine)(unsafe.Pointer(&cPoints[0])),
		C.uint32_t(n),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to CPU
		var result banderwagon.Element
		_, err := result.MultiExp(points, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	return affineToPoint(&cResult)
}

// BatchMSM performs multiple MSM operations in parallel on GPU.
func BatchMSM(pointSets [][]banderwagon.Element, scalarSets [][]fr.Element) ([]*banderwagon.Element, error) {
	n := len(pointSets)
	if n == 0 || n != len(scalarSets) {
		return nil, errors.New("mismatched input lengths")
	}

	results := make([]*banderwagon.Element, n)

	// For small batches, use sequential MSM
	if n < 4 || !Available() {
		for i := 0; i < n; i++ {
			result, err := MSM(pointSets[i], scalarSets[i])
			if err != nil {
				return nil, err
			}
			results[i] = result
		}
		return results, nil
	}

	// Use batch GPU MSM
	if err := initContext(); err != nil {
		for i := 0; i < n; i++ {
			result, err := MSM(pointSets[i], scalarSets[i])
			if err != nil {
				return nil, err
			}
			results[i] = result
		}
		return results, nil
	}

	// Determine vector size (all must be same size for batch_msm)
	vectorSize := len(pointSets[0])
	for i := 1; i < n; i++ {
		if len(pointSets[i]) != vectorSize || len(scalarSets[i]) != vectorSize {
			// Fall back to sequential if sizes differ
			for j := 0; j < n; j++ {
				result, err := MSM(pointSets[j], scalarSets[j])
				if err != nil {
					return nil, err
				}
				results[j] = result
			}
			return results, nil
		}
	}

	// Flatten all scalars
	allScalars := make([]C.BanderwagonScalar, n*vectorSize)
	for i := 0; i < n; i++ {
		for j := 0; j < vectorSize; j++ {
			bytes := scalarSets[i][j].Bytes()
			allScalars[i*vectorSize+j] = bytesToScalar(bytes[:])
		}
	}

	// Convert shared basis points
	cPoints := make([]C.BanderwagonAffine, vectorSize)
	for j := 0; j < vectorSize; j++ {
		cPoints[j] = pointToAffine(&pointSets[0][j])
	}

	// Allocate results
	cResults := make([]C.BanderwagonAffine, n)

	ret := C.metal_ipa_batch_msm(
		ctx,
		(*C.BanderwagonAffine)(unsafe.Pointer(&cResults[0])),
		(*C.BanderwagonScalar)(unsafe.Pointer(&allScalars[0])),
		(*C.BanderwagonAffine)(unsafe.Pointer(&cPoints[0])),
		C.uint32_t(n),
		C.uint32_t(vectorSize),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to sequential
		for i := 0; i < n; i++ {
			result, err := MSM(pointSets[i], scalarSets[i])
			if err != nil {
				return nil, err
			}
			results[i] = result
		}
		return results, nil
	}

	// Convert results
	for i := 0; i < n; i++ {
		result, err := affineToPoint(&cResults[i])
		if err != nil {
			return nil, err
		}
		results[i] = result
	}

	return results, nil
}

// PedersenCommit computes a Pedersen commitment using GPU.
// commitment = sum_i (values[i] * basis[i])
func PedersenCommit(basis []banderwagon.Element, values []fr.Element) (*banderwagon.Element, error) {
	return MSM(basis, values)
}

// BatchPedersenCommit computes multiple Pedersen commitments in parallel.
func BatchPedersenCommit(basis []banderwagon.Element, valueSets [][]fr.Element) ([]*banderwagon.Element, error) {
	n := len(valueSets)
	if n == 0 {
		return nil, errors.New("empty value sets")
	}

	// All commitments use the same basis
	pointSets := make([][]banderwagon.Element, n)
	for i := 0; i < n; i++ {
		if len(valueSets[i]) > len(basis) {
			return nil, errors.New("value set larger than basis")
		}
		pointSets[i] = basis[:len(valueSets[i])]
	}

	return BatchMSM(pointSets, valueSets)
}

// VerkleCommitNode computes a Verkle tree internal node commitment.
// Uses width-256 Pedersen commitment optimized for Verkle trees.
func VerkleCommitNode(children []banderwagon.Element, stem []byte) (*banderwagon.Element, error) {
	if len(children) != 256 {
		return nil, errors.New("Verkle node requires exactly 256 children")
	}

	if !Available() {
		// Fall back to CPU
		var result banderwagon.Element
		scalars := make([]fr.Element, 256)
		for i := 0; i < 256; i++ {
			scalars[i].SetOne() // Identity scalar for direct sum
		}
		_, err := result.MultiExp(children, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	if err := initContext(); err != nil {
		var result banderwagon.Element
		scalars := make([]fr.Element, 256)
		for i := 0; i < 256; i++ {
			scalars[i].SetOne()
		}
		_, err := result.MultiExp(children, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	// Convert children to C format
	cChildren := make([]C.BanderwagonAffine, 256)
	for i := 0; i < 256; i++ {
		cChildren[i] = pointToAffine(&children[i])
	}

	// Prepare stem (pad to 32 bytes if needed)
	var stemBytes [32]byte
	if len(stem) > 0 {
		copy(stemBytes[:], stem)
	}

	var cResult C.BanderwagonAffine

	ret := C.metal_verkle_commit_node(
		ctx,
		&cResult,
		(*C.BanderwagonAffine)(unsafe.Pointer(&cChildren[0])),
		(*C.uint8_t)(unsafe.Pointer(&stemBytes[0])),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to CPU
		var result banderwagon.Element
		scalars := make([]fr.Element, 256)
		for i := 0; i < 256; i++ {
			scalars[i].SetOne()
		}
		_, err := result.MultiExp(children, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	return affineToPoint(&cResult)
}

// Destroy releases the Metal IPA context.
func Destroy() {
	if ctxReady && ctx != nil {
		C.metal_ipa_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}
