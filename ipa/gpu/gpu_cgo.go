// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// Package gpu provides GPU-accelerated IPA/Verkle operations via Metal.
// This package links to luxcpp/crypto for hardware acceleration.
// Used for Verkle witness generation and verification.
package gpu

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../../luxcpp/crypto/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../../luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_ipa.h"
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
)

// Thresholds for GPU batch operations
const (
	MSMThreshold       = 64  // Min points for GPU MSM
	PedersenThreshold  = 32  // Min values for GPU Pedersen commit
	IPAVerifyThreshold = 16  // Min proofs for GPU IPA verify
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

	// Convert points to C format (affine coordinates)
	cPoints := make([]C.BanderwagonAffine, n)
	for i := 0; i < n; i++ {
		bytes := points[i].Bytes()
		for j := 0; j < 32; j++ {
			cPoints[i].x.bytes[j] = C.uint8_t(bytes[j])
		}
		// Y coordinate derived from X in banderwagon (not stored)
	}

	// Convert scalars to C format
	cScalars := make([]C.BanderwagonScalar, n)
	for i := 0; i < n; i++ {
		bytes := scalars[i].Bytes()
		for j := 0; j < 32; j++ {
			cScalars[i].bytes[j] = C.uint8_t(bytes[j])
		}
	}

	// Allocate result
	var cResult C.BanderwagonExtended

	ret := C.metal_ipa_msm(
		ctx,
		&cResult,
		(*C.BanderwagonAffine)(unsafe.Pointer(&cPoints[0])),
		(*C.BanderwagonScalar)(unsafe.Pointer(&cScalars[0])),
		C.uint32_t(n),
	)

	if ret != C.METAL_IPA_SUCCESS {
		// Fall back to CPU
		var result banderwagon.Element
		_, err := result.MultiExp(points, scalars, banderwagon.MultiExpConfig{NbTasks: 4})
		return &result, err
	}

	// Convert result back to Go type
	var resultBytes [32]byte
	for i := 0; i < 32; i++ {
		resultBytes[i] = byte(cResult.x.bytes[i])
	}

	var result banderwagon.Element
	if err := result.SetBytes(resultBytes[:]); err != nil {
		return nil, err
	}

	return &result, nil
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

	// Prepare batch data
	counts := make([]C.uint32_t, n)
	totalPoints := 0
	for i := 0; i < n; i++ {
		counts[i] = C.uint32_t(len(pointSets[i]))
		totalPoints += len(pointSets[i])
	}

	// Flatten all points and scalars
	allPoints := make([]C.BanderwagonAffine, totalPoints)
	allScalars := make([]C.BanderwagonScalar, totalPoints)
	idx := 0
	for i := 0; i < n; i++ {
		for j := 0; j < len(pointSets[i]); j++ {
			bytes := pointSets[i][j].Bytes()
			for k := 0; k < 32; k++ {
				allPoints[idx].x.bytes[k] = C.uint8_t(bytes[k])
			}
			sBytes := scalarSets[i][j].Bytes()
			for k := 0; k < 32; k++ {
				allScalars[idx].bytes[k] = C.uint8_t(sBytes[k])
			}
			idx++
		}
	}

	// Allocate results
	cResults := make([]C.BanderwagonExtended, n)

	ret := C.metal_ipa_batch_msm(
		ctx,
		(*C.BanderwagonExtended)(unsafe.Pointer(&cResults[0])),
		(*C.BanderwagonAffine)(unsafe.Pointer(&allPoints[0])),
		(*C.BanderwagonScalar)(unsafe.Pointer(&allScalars[0])),
		(*C.uint32_t)(unsafe.Pointer(&counts[0])),
		C.uint32_t(n),
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
		var resultBytes [32]byte
		for j := 0; j < 32; j++ {
			resultBytes[j] = byte(cResults[i].x.bytes[j])
		}
		var elem banderwagon.Element
		if err := elem.SetBytes(resultBytes[:]); err != nil {
			return nil, err
		}
		results[i] = &elem
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
func VerkleCommitNode(children []banderwagon.Element) (*banderwagon.Element, error) {
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
	cChildren := make([]C.BanderwagonExtended, 256)
	for i := 0; i < 256; i++ {
		bytes := children[i].Bytes()
		for j := 0; j < 32; j++ {
			cChildren[i].x.bytes[j] = C.uint8_t(bytes[j])
		}
	}

	var cResult C.BanderwagonExtended

	ret := C.metal_verkle_commit_node(
		ctx,
		&cResult,
		(*C.BanderwagonExtended)(unsafe.Pointer(&cChildren[0])),
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

	// Convert result
	var resultBytes [32]byte
	for i := 0; i < 32; i++ {
		resultBytes[i] = byte(cResult.x.bytes[i])
	}

	var result banderwagon.Element
	if err := result.SetBytes(resultBytes[:]); err != nil {
		return nil, err
	}

	return &result, nil
}

// Destroy releases the Metal IPA context.
func Destroy() {
	if ctxReady && ctx != nil {
		C.metal_ipa_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}
