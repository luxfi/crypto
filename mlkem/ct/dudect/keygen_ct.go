// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build mlkem_keygen_ct

// keygen_ct.go -- cgo bridge exposing ML-KEM-768 Keygen to the C
// dudect harness in dudect_keygen.c.
//
// CT POPULATION:
//   Both dudect classes are VALID Keygen invocations:
//     class A: keygen with fixed (zero) random tape
//     class B: keygen with random tape from a pool
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmlkem_keygen.{so,dylib} ./keygen_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"bytes"
	"unsafe"

	"github.com/luxfi/crypto/mlkem"
)

const kKeygenRandSize = 64 // ML-KEM-768 keygen tape per FIPS 203

//export mlkem_keygen_ct_setup
//
// Returns 0 on success.
func mlkem_keygen_ct_setup() C.int {
	// Smoke test: ensure the underlying API is functional with a
	// zero tape (the class-A input).
	zero := bytes.NewReader(make([]byte, kKeygenRandSize))
	_, _, err := mlkem.GenerateKeyPair(zero, mlkem.MLKEM768)
	if err != nil {
		return 1
	}
	return 0
}

//export mlkem_keygen_ct_input_size
//
// Returns the per-sample input width: 64 bytes (the keygen tape).
func mlkem_keygen_ct_input_size() C.size_t {
	return C.size_t(kKeygenRandSize)
}

//export mlkem_keygen_ct
//
// One dudect measurement sample. data points to a 64-byte tape.
func mlkem_keygen_ct(data *C.uint8_t) {
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), kKeygenRandSize)
	r := bytes.NewReader(src)
	_, _, _ = mlkem.GenerateKeyPair(r, mlkem.MLKEM768)
}

func main() {}
