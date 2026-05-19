// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build mlkem_encaps_ct

// encaps_ct.go -- cgo bridge exposing ML-KEM-768 Encaps to the C
// dudect harness in dudect_encaps.c.
//
// CT POPULATION:
//   Both dudect classes are VALID Encaps invocations under the same
//   public key, differing in the per-call random tape:
//     class A: encaps with fixed (zero) random tape
//     class B: encaps with random tape
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmlkem_encaps.{so,dylib} ./encaps_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/crypto/mlkem"
)

const kEncapsRandSize = 32

var (
	eMlkemPK *mlkem.PublicKey
)

//export mlkem_encaps_ct_setup
func mlkem_encaps_ct_setup() C.int {
	pk, _, err := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
	if err != nil {
		return 1
	}
	eMlkemPK = pk
	return 0
}

//export mlkem_encaps_ct_input_size
func mlkem_encaps_ct_input_size() C.size_t {
	return C.size_t(kEncapsRandSize)
}

//export mlkem_encaps_ct
func mlkem_encaps_ct(data *C.uint8_t) {
	if eMlkemPK == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), kEncapsRandSize)
	r := bytes.NewReader(src)
	_, _, _ = eMlkemPK.Encapsulate(r)
}

func main() {}
