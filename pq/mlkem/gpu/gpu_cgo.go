//go:build cgo

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Requires luxcpp/crypto C++ library for GPU acceleration.
// Package gpu provides GPU-accelerated ML-KEM operations via Metal/CUDA.
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
#include "lux/crypto/metal_mlkem.h"
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"unsafe"

	"github.com/luxfi/crypto/mlkem"
)

// Thresholds for GPU batch operations
const (
	BatchEncapsThreshold = 16 // Min encapsulations for GPU batch
	BatchDecapsThreshold = 16 // Min decapsulations for GPU batch
)

var (
	ctx      *C.MetalMLKEMContext
	ctxMu    sync.Mutex
	ctxReady bool
)

// initContext lazily initializes the Metal ML-KEM context.
func initContext() error {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if ctxReady {
		return nil
	}
	ctx = C.metal_mlkem_init()
	if ctx == nil {
		return errors.New("Metal ML-KEM initialization failed")
	}
	ctxReady = true
	return nil
}

// Available returns true if Metal GPU acceleration is available for ML-KEM.
func Available() bool {
	return bool(C.metal_mlkem_available())
}

// Threshold returns the minimum batch size for GPU acceleration benefit.
func Threshold() int {
	return BatchEncapsThreshold
}

// modeToC converts Go Mode to C MLKEMMode
func modeToC(mode mlkem.Mode) C.MLKEMMode {
	switch mode {
	case mlkem.MLKEM512:
		return C.MLKEM_MODE_512
	case mlkem.MLKEM768:
		return C.MLKEM_MODE_768
	case mlkem.MLKEM1024:
		return C.MLKEM_MODE_1024
	default:
		return C.MLKEM_MODE_768
	}
}

// KeyGen generates an ML-KEM key pair using GPU acceleration.
// Falls back to CPU if GPU is unavailable.
func KeyGen(mode mlkem.Mode, reader io.Reader) (*mlkem.PublicKey, *mlkem.PrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}

	if !Available() {
		return mlkem.GenerateKeyPair(reader, mode)
	}

	if err := initContext(); err != nil {
		return mlkem.GenerateKeyPair(reader, mode)
	}

	// Get expected sizes
	var pubSize, privSize int
	switch mode {
	case mlkem.MLKEM512:
		pubSize = mlkem.MLKEM512PublicKeySize
		privSize = mlkem.MLKEM512PrivateKeySize
	case mlkem.MLKEM768:
		pubSize = mlkem.MLKEM768PublicKeySize
		privSize = mlkem.MLKEM768PrivateKeySize
	case mlkem.MLKEM1024:
		pubSize = mlkem.MLKEM1024PublicKeySize
		privSize = mlkem.MLKEM1024PrivateKeySize
	default:
		return nil, nil, errors.New("invalid mode")
	}

	// Generate seed (64 bytes: d || z)
	seed := make([]byte, 64)
	if _, err := io.ReadFull(reader, seed); err != nil {
		return nil, nil, err
	}

	pubKey := make([]byte, pubSize)
	privKey := make([]byte, privSize)

	ret := C.metal_mlkem_keygen(
		ctx,
		modeToC(mode),
		(*C.uint8_t)(&pubKey[0]),
		(*C.uint8_t)(&privKey[0]),
		(*C.uint8_t)(&seed[0]),
	)

	if ret != C.METAL_MLKEM_SUCCESS {
		// Fall back to CPU
		return mlkem.GenerateKeyPair(reader, mode)
	}

	pk, err := mlkem.PublicKeyFromBytes(pubKey, mode)
	if err != nil {
		return nil, nil, err
	}

	sk, err := mlkem.PrivateKeyFromBytes(privKey, mode)
	if err != nil {
		return nil, nil, err
	}

	return pk, sk, nil
}

// BatchEncaps performs batch encapsulation using GPU acceleration.
// Returns ciphertexts and shared secrets for each public key.
// Falls back to sequential encapsulation if GPU is unavailable or count < threshold.
func BatchEncaps(pks []*mlkem.PublicKey, reader io.Reader) ([][]byte, [][]byte, error) {
	n := len(pks)
	if n == 0 {
		return nil, nil, errors.New("no public keys")
	}

	if reader == nil {
		reader = rand.Reader
	}

	// Determine mode and sizes from first public key
	if pks[0] == nil {
		return nil, nil, errors.New("nil public key")
	}

	// Get ciphertext size based on first key
	pkBytes := pks[0].Bytes()
	var mode mlkem.Mode
	var ctSize int
	switch len(pkBytes) {
	case mlkem.MLKEM512PublicKeySize:
		mode = mlkem.MLKEM512
		ctSize = mlkem.MLKEM512CiphertextSize
	case mlkem.MLKEM768PublicKeySize:
		mode = mlkem.MLKEM768
		ctSize = mlkem.MLKEM768CiphertextSize
	case mlkem.MLKEM1024PublicKeySize:
		mode = mlkem.MLKEM1024
		ctSize = mlkem.MLKEM1024CiphertextSize
	default:
		return nil, nil, errors.New("invalid public key size")
	}

	// Allocate results
	ciphertexts := make([][]byte, n)
	sharedSecrets := make([][]byte, n)
	for i := range ciphertexts {
		ciphertexts[i] = make([]byte, ctSize)
		sharedSecrets[i] = make([]byte, 32)
	}

	// Fall back to sequential for small batches or no GPU
	if n < BatchEncapsThreshold || !Available() {
		for i := 0; i < n; i++ {
			if pks[i] == nil {
				return nil, nil, errors.New("nil public key in batch")
			}
			ct, ss, err := pks[i].Encapsulate(reader)
			if err != nil {
				return nil, nil, err
			}
			ciphertexts[i] = ct
			sharedSecrets[i] = ss
		}
		return ciphertexts, sharedSecrets, nil
	}

	if err := initContext(); err != nil {
		// Fall back to sequential
		for i := 0; i < n; i++ {
			ct, ss, err := pks[i].Encapsulate(reader)
			if err != nil {
				return nil, nil, err
			}
			ciphertexts[i] = ct
			sharedSecrets[i] = ss
		}
		return ciphertexts, sharedSecrets, nil
	}

	// Generate randomness for all encapsulations
	randomness := make([]byte, n*32)
	if _, err := io.ReadFull(reader, randomness); err != nil {
		return nil, nil, err
	}

	// Prepare C arrays
	ctPtrs := make([]*C.uint8_t, n)
	pkPtrs := make([]*C.uint8_t, n)
	pkBytesAll := make([][]byte, n)
	ssFlat := make([]byte, n*32)

	for i := 0; i < n; i++ {
		if pks[i] == nil {
			return nil, nil, errors.New("nil public key in batch")
		}
		pkBytesAll[i] = pks[i].Bytes()
		ctPtrs[i] = (*C.uint8_t)(&ciphertexts[i][0])
		pkPtrs[i] = (*C.uint8_t)(&pkBytesAll[i][0])
	}

	ret := C.metal_mlkem_batch_encaps(
		ctx,
		modeToC(mode),
		(**C.uint8_t)(unsafe.Pointer(&ctPtrs[0])),
		(*C.uint8_t)(&ssFlat[0]),
		(**C.uint8_t)(unsafe.Pointer(&pkPtrs[0])),
		(*C.uint8_t)(&randomness[0]),
		C.uint32_t(n),
	)

	if ret != C.METAL_MLKEM_SUCCESS {
		// Fall back to sequential
		for i := 0; i < n; i++ {
			ct, ss, err := pks[i].Encapsulate(reader)
			if err != nil {
				return nil, nil, err
			}
			ciphertexts[i] = ct
			sharedSecrets[i] = ss
		}
		return ciphertexts, sharedSecrets, nil
	}

	// Extract shared secrets from flat array
	for i := 0; i < n; i++ {
		copy(sharedSecrets[i], ssFlat[i*32:(i+1)*32])
	}

	return ciphertexts, sharedSecrets, nil
}

// BatchDecaps performs batch decapsulation using GPU acceleration.
// Returns shared secrets for each ciphertext.
// Falls back to sequential decapsulation if GPU is unavailable or count < threshold.
func BatchDecaps(sk *mlkem.PrivateKey, ciphertexts [][]byte) ([][]byte, error) {
	n := len(ciphertexts)
	if n == 0 {
		return nil, errors.New("no ciphertexts")
	}
	if sk == nil {
		return nil, errors.New("nil private key")
	}

	// Allocate results
	sharedSecrets := make([][]byte, n)
	for i := range sharedSecrets {
		sharedSecrets[i] = make([]byte, 32)
	}

	// Fall back to sequential for small batches or no GPU
	if n < BatchDecapsThreshold || !Available() {
		for i := 0; i < n; i++ {
			ss, err := sk.Decapsulate(ciphertexts[i])
			if err != nil {
				return nil, err
			}
			sharedSecrets[i] = ss
		}
		return sharedSecrets, nil
	}

	if err := initContext(); err != nil {
		// Fall back to sequential
		for i := 0; i < n; i++ {
			ss, err := sk.Decapsulate(ciphertexts[i])
			if err != nil {
				return nil, err
			}
			sharedSecrets[i] = ss
		}
		return sharedSecrets, nil
	}

	// Get mode from private key bytes
	skBytes := sk.Bytes()
	var mode mlkem.Mode
	switch len(skBytes) {
	case mlkem.MLKEM512PrivateKeySize:
		mode = mlkem.MLKEM512
	case mlkem.MLKEM768PrivateKeySize:
		mode = mlkem.MLKEM768
	case mlkem.MLKEM1024PrivateKeySize:
		mode = mlkem.MLKEM1024
	default:
		return nil, errors.New("invalid private key size")
	}

	// Prepare C arrays
	ctPtrs := make([]*C.uint8_t, n)
	ssFlat := make([]byte, n*32)

	for i := 0; i < n; i++ {
		if len(ciphertexts[i]) == 0 {
			return nil, errors.New("empty ciphertext in batch")
		}
		ctPtrs[i] = (*C.uint8_t)(&ciphertexts[i][0])
	}

	ret := C.metal_mlkem_batch_decaps(
		ctx,
		modeToC(mode),
		(*C.uint8_t)(&ssFlat[0]),
		(**C.uint8_t)(unsafe.Pointer(&ctPtrs[0])),
		(*C.uint8_t)(&skBytes[0]),
		C.uint32_t(n),
	)

	if ret != C.METAL_MLKEM_SUCCESS {
		// Fall back to sequential
		for i := 0; i < n; i++ {
			ss, err := sk.Decapsulate(ciphertexts[i])
			if err != nil {
				return nil, err
			}
			sharedSecrets[i] = ss
		}
		return sharedSecrets, nil
	}

	// Extract shared secrets from flat array
	for i := 0; i < n; i++ {
		copy(sharedSecrets[i], ssFlat[i*32:(i+1)*32])
	}

	return sharedSecrets, nil
}

// Mode returns the current GPU mode information.
func Mode() string {
	if Available() {
		return "Metal GPU"
	}
	return "CPU fallback"
}

// Destroy releases the Metal ML-KEM context.
// Should be called when done with GPU ML-KEM operations.
func Destroy() {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if ctxReady && ctx != nil {
		C.metal_mlkem_destroy(ctx)
		ctx = nil
		ctxReady = false
	}
}
