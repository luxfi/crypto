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
// CT POPULATION (canonical KEM-Decaps dudect framing):
//
//   class A: a fixed VALID ciphertext encapsulated under the matching pk.
//   class B: the caller-supplied bytes treated AS a ciphertext directly
//            (almost-always invalid → exercises the FO implicit-rejection
//            branch in Decaps).
//
// IND-CCA2 secure ML-KEM uses Fujisaki-Okamoto implicit rejection: for
// an invalid ciphertext, Decaps returns a pseudorandom value derived
// from the secret key + ciphertext, NOT an error. The CT property is
// that VALID and INVALID ciphertexts must take indistinguishable time.
// A timing difference between them is a textbook IND-CCA2 timing leak
// (the FO-K attack class).
//
// This is the dudect framing the cloudflare/circl ML-KEM-768 backend
// is documented constant-time over (BoringSSL / libjade-grade).
//
// The dudect_decaps.c harness owns the class-A/class-B partition: for
// class A, it copies the fixed reference ciphertext bytes into `data`;
// for class B, it leaves `data` containing per-sample random bytes.
// The Go bridge does not pick the class — it just dispatches Decaps.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmlkem_decaps.{so,dylib} ./decaps_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/crypto/mlkem"
)

var (
	dMlkemSK *mlkem.PrivateKey
	// dMlkemValidCT is the canonical class-A ciphertext: a real,
	// valid encapsulation under dMlkemSK's public key. The C harness
	// copies these bytes into class-A samples verbatim.
	dMlkemValidCT []byte
	// dMlkemCTSize is the FIPS 203 ML-KEM-768 ciphertext size (1088 bytes).
	dMlkemCTSize int
)

//export mlkem_decaps_ct_setup
func mlkem_decaps_ct_setup() C.int {
	pk, sk, err := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
	if err != nil {
		return 1
	}
	ct, _, err := pk.Encapsulate()
	if err != nil {
		return 2
	}
	dMlkemSK = sk
	dMlkemValidCT = ct
	dMlkemCTSize = len(ct)
	return 0
}

// Returns the per-sample input width (FIPS 203 ML-KEM-768 ciphertext
// is 1088 bytes). Named "pool_size" for harness API compatibility.
//
//export mlkem_decaps_ct_pool_size
func mlkem_decaps_ct_pool_size() C.size_t {
	return C.size_t(dMlkemCTSize)
}

// Same as pool_size — full ciphertext bytes per sample.
//
//export mlkem_decaps_ct_input_size
func mlkem_decaps_ct_input_size() C.size_t {
	return C.size_t(dMlkemCTSize)
}

// Copies the class-A reference ciphertext into the caller-supplied C
// buffer (must be at least mlkem_decaps_ct_input_size() bytes). Returns
// 0 on success. Avoids passing a Go pointer back through cgo (which
// would trip Go 1.26's cgocheck=1 unpinned-pointer panic).
//
//export mlkem_decaps_ct_copy_valid_ct
func mlkem_decaps_ct_copy_valid_ct(dst *C.uint8_t) C.int {
	if len(dMlkemValidCT) == 0 || dst == nil {
		return 1
	}
	C.memcpy(unsafe.Pointer(dst), unsafe.Pointer(&dMlkemValidCT[0]), C.size_t(dMlkemCTSize))
	return 0
}

// One dudect sample: decapsulate the per-sample bytes. Class A → valid
// reference ciphertext (FO-accept branch). Class B → caller-random
// bytes (FO-reject branch via implicit rejection). Output is discarded;
// dudect measures wall-clock cycles, not return value.
//
// Critical: this function MUST be branchless in its dispatch — only
// the Decaps call may differ between samples. Any data-dependent
// branch here would surface as a harness artifact.
//
//export mlkem_decaps_ct
func mlkem_decaps_ct(data *C.uint8_t) {
	if dMlkemSK == nil {
		return
	}
	ct := unsafe.Slice((*byte)(unsafe.Pointer(data)), dMlkemCTSize)
	_, _ = dMlkemSK.Decapsulate(ct)
}

func main() {}
