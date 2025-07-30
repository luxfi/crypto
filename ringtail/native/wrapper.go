// SPDX-License-Identifier: BUSL-1.1
// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.

package native

/*
#cgo CFLAGS: -O3 -march=native -mtune=native
#cgo LDFLAGS: -lringtail

#include <stdint.h>
#include <stdlib.h>

// Ringtail native functions (implemented in Rust/C)
extern int rt_keygen(const uint8_t* seed, uint8_t* sk, uint8_t* pk);
extern int rt_precompute(const uint8_t* sk, uint8_t* precomp);
extern int rt_quick_sign(const uint8_t* precomp, const uint8_t* msg, uint8_t* sig);
extern int rt_verify_share(const uint8_t* pk, const uint8_t* msg, const uint8_t* sig);
extern int rt_aggregate(const uint8_t** shares, int n, uint8_t* cert);
extern int rt_verify(const uint8_t* pk, const uint8_t* msg, const uint8_t* cert);
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	SKSize      = 8192  // Secret key size
	PKSize      = 4096  // Public key size
	PrecompSize = 40960 // Precomputed data size (~40KB)
	ShareSize   = 430   // Share size
	CertSize    = 3072  // Certificate size (~3KB)
)

// RTKeyGen generates a Ringtail key pair from seed
func RTKeyGen(seed []byte) (sk, pk []byte, err error) {
	if len(seed) != 32 {
		return nil, nil, errors.New("seed must be 32 bytes")
	}

	sk = make([]byte, SKSize)
	pk = make([]byte, PKSize)

	ret := C.rt_keygen(
		(*C.uint8_t)(unsafe.Pointer(&seed[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
	)

	if ret != 0 {
		return nil, nil, errors.New("keygen failed")
	}

	return sk, pk, nil
}

// RTPrecompute generates precomputed data for fast signing
func RTPrecompute(sk []byte) ([]byte, error) {
	if len(sk) != SKSize {
		return nil, errors.New("invalid secret key size")
	}

	precomp := make([]byte, PrecompSize)

	ret := C.rt_precompute(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&precomp[0])),
	)

	if ret != 0 {
		return nil, errors.New("precompute failed")
	}

	return precomp, nil
}

// RTQuickSign creates a signature share using precomputed data
func RTQuickSign(precomp, msg []byte) ([]byte, error) {
	if len(precomp) != PrecompSize {
		return nil, errors.New("invalid precomp size")
	}
	if len(msg) != 32 {
		return nil, errors.New("msg must be 32 bytes")
	}

	sig := make([]byte, ShareSize)

	ret := C.rt_quick_sign(
		(*C.uint8_t)(unsafe.Pointer(&precomp[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)

	if ret != 0 {
		return nil, errors.New("quick sign failed")
	}

	return sig, nil
}

// RTVerifyShare verifies a single share
func RTVerifyShare(pk, msg, share []byte) bool {
	if len(pk) != PKSize || len(msg) != 32 || len(share) != ShareSize {
		return false
	}

	ret := C.rt_verify_share(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		(*C.uint8_t)(unsafe.Pointer(&share[0])),
	)

	return ret == 0
}

// RTAggregate combines shares into a certificate
func RTAggregate(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares to aggregate")
	}

	// Create array of pointers to shares
	sharePtrs := make([]*C.uint8_t, len(shares))
	for i, share := range shares {
		if len(share) != ShareSize {
			return nil, errors.New("invalid share size")
		}
		sharePtrs[i] = (*C.uint8_t)(unsafe.Pointer(&share[0]))
	}

	cert := make([]byte, CertSize)

	ret := C.rt_aggregate(
		(**C.uint8_t)(unsafe.Pointer(&sharePtrs[0])),
		C.int(len(shares)),
		(*C.uint8_t)(unsafe.Pointer(&cert[0])),
	)

	if ret != 0 {
		return nil, errors.New("aggregate failed")
	}

	return cert, nil
}

// RTVerify verifies an aggregate certificate
func RTVerify(pk, msg, cert []byte) bool {
	if len(pk) != PKSize || len(msg) != 32 || len(cert) != CertSize {
		return false
	}

	ret := C.rt_verify(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		(*C.uint8_t)(unsafe.Pointer(&cert[0])),
	)

	return ret == 0
}