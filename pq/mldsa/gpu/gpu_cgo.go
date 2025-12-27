//go:build cgo

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Requires luxcpp/crypto C++ library for GPU acceleration.
// Package gpu provides GPU-accelerated ML-DSA operations via Metal/CUDA.
// This package links to luxcpp/crypto for hardware acceleration.
// The C++ library handles automatic fallback to CPU when GPU is unavailable.
package gpu

/*
#cgo pkg-config: lux-crypto-only
#cgo darwin LDFLAGS: -framework Metal -framework Foundation
#cgo linux LDFLAGS: 

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_mldsa.h"
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/luxfi/crypto/mldsa"
)

// Thresholds for GPU batch operations
const (
	BatchSignThreshold   = 16 // Min signatures for GPU batch sign
	BatchVerifyThreshold = 32 // Min signatures for GPU batch verify
)

var (
	ctx      *C.MetalMLDSAContext
	ctxMu    sync.Mutex
	ctxReady bool
)

// initContext lazily initializes the Metal ML-DSA context.
func initContext() error {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if ctxReady {
		return nil
	}
	ctx = C.metal_mldsa_init()
	if ctx == nil {
		return errors.New("Metal ML-DSA initialization failed")
	}
	ctxReady = true
	return nil
}

// Available returns true if Metal GPU acceleration is available for ML-DSA.
func Available() bool {
	return bool(C.metal_mldsa_available())
}

// Threshold returns the minimum batch size for GPU acceleration benefit.
func Threshold() int {
	return BatchVerifyThreshold
}

// modeToC converts Go Mode to C MLDSAMode
func modeToC(mode mldsa.Mode) C.MLDSAMode {
	switch mode {
	case mldsa.MLDSA44:
		return C.MLDSA_MODE_44
	case mldsa.MLDSA65:
		return C.MLDSA_MODE_65
	case mldsa.MLDSA87:
		return C.MLDSA_MODE_87
	default:
		return C.MLDSA_MODE_65
	}
}

// getPrivKeyMode extracts mode from private key bytes
func getPrivKeyMode(priv *mldsa.PrivateKey) mldsa.Mode {
	if priv == nil {
		return mldsa.MLDSA65
	}
	privBytes := priv.Bytes()
	switch len(privBytes) {
	case mldsa.MLDSA44PrivateKeySize:
		return mldsa.MLDSA44
	case mldsa.MLDSA65PrivateKeySize:
		return mldsa.MLDSA65
	case mldsa.MLDSA87PrivateKeySize:
		return mldsa.MLDSA87
	default:
		return mldsa.MLDSA65
	}
}

// getPubKeyMode extracts mode from public key bytes
func getPubKeyMode(pub *mldsa.PublicKey) mldsa.Mode {
	if pub == nil {
		return mldsa.MLDSA65
	}
	pubBytes := pub.Bytes()
	switch len(pubBytes) {
	case mldsa.MLDSA44PublicKeySize:
		return mldsa.MLDSA44
	case mldsa.MLDSA65PublicKeySize:
		return mldsa.MLDSA65
	case mldsa.MLDSA87PublicKeySize:
		return mldsa.MLDSA87
	default:
		return mldsa.MLDSA65
	}
}

// KeyGen generates an ML-DSA key pair using GPU acceleration.
// Falls back to CPU if GPU is unavailable.
func KeyGen(mode mldsa.Mode, seed []byte) (*mldsa.PrivateKey, error) {
	if !Available() || len(seed) != 32 {
		// Fall back to CPU
		return mldsa.GenerateKey(nil, mode)
	}

	if err := initContext(); err != nil {
		return mldsa.GenerateKey(nil, mode)
	}

	// Get expected sizes
	var pubSize, privSize int
	switch mode {
	case mldsa.MLDSA44:
		pubSize = mldsa.MLDSA44PublicKeySize
		privSize = mldsa.MLDSA44PrivateKeySize
	case mldsa.MLDSA65:
		pubSize = mldsa.MLDSA65PublicKeySize
		privSize = mldsa.MLDSA65PrivateKeySize
	case mldsa.MLDSA87:
		pubSize = mldsa.MLDSA87PublicKeySize
		privSize = mldsa.MLDSA87PrivateKeySize
	default:
		return nil, mldsa.ErrInvalidMode
	}

	pubKey := make([]byte, pubSize)
	privKey := make([]byte, privSize)

	ret := C.metal_mldsa_keygen(
		ctx,
		modeToC(mode),
		(*C.uint8_t)(&pubKey[0]),
		(*C.uint8_t)(&privKey[0]),
		(*C.uint8_t)(&seed[0]),
	)

	if ret != C.METAL_MLDSA_SUCCESS {
		// Fall back to CPU
		return mldsa.GenerateKey(nil, mode)
	}

	return mldsa.PrivateKeyFromBytes(mode, privKey)
}

// BatchSign signs multiple messages using GPU acceleration.
// All messages are signed with the same private key.
// Falls back to sequential signing if GPU is unavailable or count < threshold.
func BatchSign(priv *mldsa.PrivateKey, messages [][]byte) ([][]byte, error) {
	n := len(messages)
	if n == 0 {
		return nil, errors.New("no messages to sign")
	}
	if priv == nil {
		return nil, errors.New("nil private key")
	}

	// Get mode and signature size
	mode := getPrivKeyMode(priv)
	sigSize := mldsa.GetSignatureSize(mode)

	// Allocate result slice
	signatures := make([][]byte, n)
	for i := range signatures {
		signatures[i] = make([]byte, sigSize)
	}

	// Fall back to sequential for small batches or no GPU
	if n < BatchSignThreshold || !Available() {
		for i := 0; i < n; i++ {
			sig, err := priv.Sign(nil, messages[i], nil)
			if err != nil {
				return nil, err
			}
			signatures[i] = sig
		}
		return signatures, nil
	}

	if err := initContext(); err != nil {
		// Fall back to sequential on init error
		for i := 0; i < n; i++ {
			sig, err := priv.Sign(nil, messages[i], nil)
			if err != nil {
				return nil, err
			}
			signatures[i] = sig
		}
		return signatures, nil
	}

	// Prepare C arrays
	sigPtrs := make([]*C.uint8_t, n)
	msgPtrs := make([]*C.uint8_t, n)
	msgLens := make([]C.size_t, n)

	for i := 0; i < n; i++ {
		sigPtrs[i] = (*C.uint8_t)(&signatures[i][0])
		if len(messages[i]) > 0 {
			msgPtrs[i] = (*C.uint8_t)(&messages[i][0])
		}
		msgLens[i] = C.size_t(len(messages[i]))
	}

	privBytes := priv.Bytes()

	ret := C.metal_mldsa_batch_sign(
		ctx,
		modeToC(mode),
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(*C.uint8_t)(&privBytes[0]),
		(**C.uint8_t)(unsafe.Pointer(&msgPtrs[0])),
		(*C.size_t)(&msgLens[0]),
		C.uint32_t(n),
	)

	if ret != C.METAL_MLDSA_SUCCESS {
		// Fall back to sequential on GPU error
		for i := 0; i < n; i++ {
			sig, err := priv.Sign(nil, messages[i], nil)
			if err != nil {
				return nil, err
			}
			signatures[i] = sig
		}
	}

	return signatures, nil
}

// BatchVerify verifies multiple ML-DSA signatures using GPU acceleration.
// Returns a slice of booleans indicating validity of each signature.
// Falls back to sequential verification if GPU is unavailable or count < threshold.
func BatchVerify(pks []*mldsa.PublicKey, sigs [][]byte, msgs [][]byte) ([]bool, error) {
	n := len(pks)
	if n == 0 || n != len(sigs) || n != len(msgs) {
		return nil, errors.New("mismatched input lengths")
	}

	results := make([]bool, n)

	// Determine mode from first public key
	if pks[0] == nil {
		return nil, errors.New("nil public key")
	}
	mode := getPubKeyMode(pks[0])

	// Fall back to sequential for small batches or no GPU
	if n < BatchVerifyThreshold || !Available() {
		for i := 0; i < n; i++ {
			if pks[i] == nil {
				results[i] = false
				continue
			}
			results[i] = pks[i].Verify(msgs[i], sigs[i], nil)
		}
		return results, nil
	}

	if err := initContext(); err != nil {
		// Fall back to sequential on init error
		for i := 0; i < n; i++ {
			if pks[i] == nil {
				results[i] = false
				continue
			}
			results[i] = pks[i].Verify(msgs[i], sigs[i], nil)
		}
		return results, nil
	}

	// Prepare C arrays
	pkPtrs := make([]*C.uint8_t, n)
	sigPtrs := make([]*C.uint8_t, n)
	msgPtrs := make([]*C.uint8_t, n)
	msgLens := make([]C.size_t, n)
	intResults := make([]C.int, n)

	// Serialize keys and signatures
	pkBytes := make([][]byte, n)

	for i := 0; i < n; i++ {
		if pks[i] == nil {
			return nil, errors.New("nil public key in batch")
		}
		pkBytes[i] = pks[i].Bytes()

		pkPtrs[i] = (*C.uint8_t)(&pkBytes[i][0])
		if len(sigs[i]) > 0 {
			sigPtrs[i] = (*C.uint8_t)(&sigs[i][0])
		}
		if len(msgs[i]) > 0 {
			msgPtrs[i] = (*C.uint8_t)(&msgs[i][0])
		}
		msgLens[i] = C.size_t(len(msgs[i]))
	}

	ret := C.metal_mldsa_batch_verify(
		ctx,
		modeToC(mode),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(**C.uint8_t)(unsafe.Pointer(&msgPtrs[0])),
		(*C.size_t)(&msgLens[0]),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&intResults[0])),
	)

	if ret < 0 {
		// GPU error, fall back to sequential
		for i := 0; i < n; i++ {
			if pks[i] == nil {
				results[i] = false
				continue
			}
			results[i] = pks[i].Verify(msgs[i], sigs[i], nil)
		}
		return results, nil
	}

	// Convert results
	for i := 0; i < n; i++ {
		results[i] = intResults[i] != 0
	}

	return results, nil
}

// Mode returns the current GPU mode information.
func Mode() string {
	if Available() {
		return "Metal GPU"
	}
	return "CPU fallback"
}

// Destroy releases the Metal ML-DSA context.
// Should be called when done with GPU ML-DSA operations.
func Destroy() {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if ctxReady && ctx != nil {
		C.metal_mldsa_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}
