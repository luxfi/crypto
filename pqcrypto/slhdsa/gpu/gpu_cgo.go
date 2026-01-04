// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && metal && (darwin || linux)

// Package gpu provides GPU-accelerated SLH-DSA operations via Metal/CUDA.
// This package links to luxcpp/crypto for hardware acceleration.
// The C++ library handles automatic fallback to CPU when GPU is unavailable.
//
// SLH-DSA (FIPS 205, formerly SPHINCS+) is a hash-based signature scheme.
// GPU acceleration focuses on parallel hash tree computations.
package gpu

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../../../luxcpp/crypto/include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../../../../luxcpp/crypto/build-local -lluxcrypto -framework Metal -framework Foundation
#cgo linux LDFLAGS: -L${SRCDIR}/../../../../../../luxcpp/crypto/build-local -lluxcrypto

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lux/crypto/metal_slhdsa.h"
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/luxfi/crypto/slhdsa"
)

// Thresholds for GPU batch operations
const (
	BatchSignThreshold   = 8  // Min signatures for GPU batch sign
	BatchVerifyThreshold = 16 // Min signatures for GPU batch verify
)

var (
	ctx      *C.MetalSLHDSAContext
	ctxMu    sync.Mutex
	ctxReady bool
)

// initContext lazily initializes the Metal SLH-DSA context.
func initContext() error {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if ctxReady {
		return nil
	}
	ctx = C.metal_slhdsa_init()
	if ctx == nil {
		return errors.New("Metal SLH-DSA initialization failed")
	}
	ctxReady = true
	return nil
}

// Available returns true if Metal GPU acceleration is available for SLH-DSA.
func Available() bool {
	return bool(C.metal_slhdsa_available())
}

// Threshold returns the minimum batch size for GPU acceleration benefit.
func Threshold() int {
	return BatchVerifyThreshold
}

// modeToC converts Go Mode to C SLHDSAMode
func modeToC(mode slhdsa.Mode) C.SLHDSAMode {
	switch mode {
	case slhdsa.SHA2_128s:
		return C.SLHDSA_SHA2_128s
	case slhdsa.SHAKE_128s:
		return C.SLHDSA_SHAKE_128s
	case slhdsa.SHA2_128f:
		return C.SLHDSA_SHA2_128f
	case slhdsa.SHAKE_128f:
		return C.SLHDSA_SHAKE_128f
	case slhdsa.SHA2_192s:
		return C.SLHDSA_SHA2_192s
	case slhdsa.SHAKE_192s:
		return C.SLHDSA_SHAKE_192s
	case slhdsa.SHA2_192f:
		return C.SLHDSA_SHA2_192f
	case slhdsa.SHAKE_192f:
		return C.SLHDSA_SHAKE_192f
	case slhdsa.SHA2_256s:
		return C.SLHDSA_SHA2_256s
	case slhdsa.SHAKE_256s:
		return C.SLHDSA_SHAKE_256s
	case slhdsa.SHA2_256f:
		return C.SLHDSA_SHA2_256f
	case slhdsa.SHAKE_256f:
		return C.SLHDSA_SHAKE_256f
	default:
		return C.SLHDSA_SHA2_128s
	}
}

// KeyGen generates an SLH-DSA key pair using GPU acceleration.
// Falls back to CPU if GPU is unavailable.
func KeyGen(mode slhdsa.Mode, seed []byte) (*slhdsa.PrivateKey, error) {
	// Determine required seed size based on security level
	var seedSize int
	switch mode {
	case slhdsa.SHA2_128s, slhdsa.SHAKE_128s, slhdsa.SHA2_128f, slhdsa.SHAKE_128f:
		seedSize = 16
	case slhdsa.SHA2_192s, slhdsa.SHAKE_192s, slhdsa.SHA2_192f, slhdsa.SHAKE_192f:
		seedSize = 24
	case slhdsa.SHA2_256s, slhdsa.SHAKE_256s, slhdsa.SHA2_256f, slhdsa.SHAKE_256f:
		seedSize = 32
	default:
		return nil, slhdsa.ErrInvalidMode
	}

	if !Available() || len(seed) != seedSize*3 { // SLH-DSA needs 3n bytes
		// Fall back to CPU
		return slhdsa.GenerateKey(nil, mode)
	}

	if err := initContext(); err != nil {
		return slhdsa.GenerateKey(nil, mode)
	}

	// Get expected sizes
	pubSize := slhdsa.GetPublicKeySize(mode)
	var privSize int
	switch mode {
	case slhdsa.SHA2_128s, slhdsa.SHAKE_128s, slhdsa.SHA2_128f, slhdsa.SHAKE_128f:
		privSize = 64
	case slhdsa.SHA2_192s, slhdsa.SHAKE_192s, slhdsa.SHA2_192f, slhdsa.SHAKE_192f:
		privSize = 96
	case slhdsa.SHA2_256s, slhdsa.SHAKE_256s, slhdsa.SHA2_256f, slhdsa.SHAKE_256f:
		privSize = 128
	}

	if pubSize == 0 || privSize == 0 {
		return nil, slhdsa.ErrInvalidMode
	}

	pubKey := make([]byte, pubSize)
	privKey := make([]byte, privSize)

	ret := C.metal_slhdsa_keygen(
		ctx,
		modeToC(mode),
		(*C.uint8_t)(&pubKey[0]),
		(*C.uint8_t)(&privKey[0]),
		(*C.uint8_t)(&seed[0]),
	)

	if ret != C.METAL_SLHDSA_SUCCESS {
		// Fall back to CPU
		return slhdsa.GenerateKey(nil, mode)
	}

	return slhdsa.PrivateKeyFromBytes(mode, privKey)
}

// BatchSign signs multiple messages using GPU acceleration.
// All messages are signed with the same private key.
// Falls back to sequential signing if GPU is unavailable or count < threshold.
func BatchSign(priv *slhdsa.PrivateKey, messages [][]byte) ([][]byte, error) {
	n := len(messages)
	if n == 0 {
		return nil, errors.New("no messages to sign")
	}
	if priv == nil {
		return nil, errors.New("nil private key")
	}

	// Get mode and signature size
	mode := getPrivKeyMode(priv)
	sigSize := slhdsa.GetSignatureSize(mode)

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

	ret := C.metal_slhdsa_batch_sign(
		ctx,
		modeToC(mode),
		(**C.uint8_t)(unsafe.Pointer(&sigPtrs[0])),
		(*C.uint8_t)(&privBytes[0]),
		(**C.uint8_t)(unsafe.Pointer(&msgPtrs[0])),
		(*C.size_t)(&msgLens[0]),
		C.uint32_t(n),
	)

	if ret != C.METAL_SLHDSA_SUCCESS {
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

// BatchVerify verifies multiple SLH-DSA signatures using GPU acceleration.
// Returns a slice of booleans indicating validity of each signature.
// Falls back to sequential verification if GPU is unavailable or count < threshold.
func BatchVerify(pks []*slhdsa.PublicKey, sigs [][]byte, msgs [][]byte) ([]bool, error) {
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

	ret := C.metal_slhdsa_batch_verify(
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

// GPUMode returns the current GPU mode information.
func GPUMode() string {
	if Available() {
		return "Metal GPU"
	}
	return "CPU fallback"
}

// Destroy releases the Metal SLH-DSA context.
// Should be called when done with GPU SLH-DSA operations.
func Destroy() {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if ctxReady && ctx != nil {
		C.metal_slhdsa_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}

// getPrivKeyMode extracts mode from private key bytes
func getPrivKeyMode(priv *slhdsa.PrivateKey) slhdsa.Mode {
	if priv == nil {
		return slhdsa.SHA2_128s
	}
	// Determine mode from key size
	privBytes := priv.Bytes()
	switch len(privBytes) {
	case 64:
		return slhdsa.SHA2_128s // 128-bit security
	case 96:
		return slhdsa.SHA2_192s // 192-bit security
	case 128:
		return slhdsa.SHA2_256s // 256-bit security
	default:
		return slhdsa.SHA2_128s
	}
}

// getPubKeyMode extracts mode from public key bytes
func getPubKeyMode(pub *slhdsa.PublicKey) slhdsa.Mode {
	if pub == nil {
		return slhdsa.SHA2_128s
	}
	// Determine mode from key size
	pubBytes := pub.Bytes()
	switch len(pubBytes) {
	case 32:
		return slhdsa.SHA2_128s // 128-bit security
	case 48:
		return slhdsa.SHA2_192s // 192-bit security
	case 64:
		return slhdsa.SHA2_256s // 256-bit security
	default:
		return slhdsa.SHA2_128s
	}
}
