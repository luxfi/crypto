// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build mlkem_decaps_ct

// decaps_ct.go -- cgo bridge exposing ML-KEM-768 Decaps to the C
// dudect harness in dudect_decaps.c.
//
// DECAPS IS THE MOST CT-CRITICAL ML-KEM ROUTINE. An adversary that
// submits chosen ciphertexts and observes timing channels can
// extract bits of the secret key (a.k.a. the FO-K attack class).
// The Lux Go implementation wraps cloudflare/circl's mlkem768
// scheme, which is BoringSSL/libjade-grade CT.
//
// CT POPULATION:
//   Both dudect classes are VALID Decaps invocations under the same
//   secret key, on a pool of valid ciphertexts pre-generated under
//   the matching public key. All inputs are valid; any timing
//   difference is a real ciphertext-content-dependent signal.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmlkem_decaps.{so,dylib} ./decaps_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/crypto/mlkem"
)

const kDecapsValidPool = 64

var (
	dMlkemSK   *mlkem.PrivateKey
	dMlkemPool [kDecapsValidPool][]byte
)

//export mlkem_decaps_ct_setup
func mlkem_decaps_ct_setup() C.int {
	pk, sk, err := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
	if err != nil {
		return 1
	}
	for i := 0; i < kDecapsValidPool; i++ {
		ct, _, err := pk.Encapsulate()
		if err != nil {
			return 2
		}
		dMlkemPool[i] = ct
	}
	dMlkemSK = sk
	return 0
}

//export mlkem_decaps_ct_pool_size
func mlkem_decaps_ct_pool_size() C.size_t {
	return C.size_t(kDecapsValidPool)
}

//export mlkem_decaps_ct_input_size
//
// Returns the per-sample input width: 4 bytes (a big-endian uint32
// pool index, mod kDecapsValidPool).
func mlkem_decaps_ct_input_size() C.size_t {
	return C.size_t(4)
}

//export mlkem_decaps_ct
func mlkem_decaps_ct(data *C.uint8_t) {
	if dMlkemSK == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), 4)
	idx := (uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])) %
		uint32(kDecapsValidPool)
	_, _ = dMlkemSK.Decapsulate(dMlkemPool[idx])
}

func main() {}
