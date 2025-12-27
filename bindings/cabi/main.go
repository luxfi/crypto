// Package main exports lux/crypto PQ functions as a C shared library.
//
// Build:
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libluxcrypto.so ./bindings/cabi/
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libluxcrypto.dylib ./bindings/cabi/  # macOS
//
// This produces libluxcrypto.{so,dylib,dll} + libluxcrypto.h
// which Python (ctypes/cffi), TypeScript (N-API/WASM), and Rust (FFI) can bind to.
package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
)

// ═══════════════════════════════════════════════════════════════════════
// ML-KEM-768 (FIPS 203)
// ═══════════════════════════════════════════════════════════════════════

//export lux_mlkem768_keypair
func lux_mlkem768_keypair(pk *C.char, pkLen *C.int, sk *C.char, skLen *C.int) C.int {
	pub, priv, err := mlkem.GenerateKey(mlkem.MLKEM768)
	if err != nil {
		return -1
	}

	pubBytes := pub.Bytes()
	privBytes := priv.Bytes()

	*pkLen = C.int(len(pubBytes))
	*skLen = C.int(len(privBytes))
	C.memcpy(unsafe.Pointer(pk), unsafe.Pointer(&pubBytes[0]), C.size_t(len(pubBytes)))
	C.memcpy(unsafe.Pointer(sk), unsafe.Pointer(&privBytes[0]), C.size_t(len(privBytes)))

	return 0
}

//export lux_mlkem768_encapsulate
func lux_mlkem768_encapsulate(
	pkData *C.char, pkLen C.int,
	ct *C.char, ctLen *C.int,
	ss *C.char, ssLen *C.int,
) C.int {
	pkBytes := C.GoBytes(unsafe.Pointer(pkData), pkLen)
	pub, err := mlkem.PublicKeyFromBytes(pkBytes, mlkem.MLKEM768)
	if err != nil {
		return -1
	}

	ciphertext, sharedSecret, err := pub.Encapsulate()
	if err != nil {
		return -2
	}

	*ctLen = C.int(len(ciphertext))
	*ssLen = C.int(len(sharedSecret))
	C.memcpy(unsafe.Pointer(ct), unsafe.Pointer(&ciphertext[0]), C.size_t(len(ciphertext)))
	C.memcpy(unsafe.Pointer(ss), unsafe.Pointer(&sharedSecret[0]), C.size_t(len(sharedSecret)))

	return 0
}

//export lux_mlkem768_decapsulate
func lux_mlkem768_decapsulate(
	skData *C.char, skLen C.int,
	ctData *C.char, ctLen C.int,
	ss *C.char, ssLen *C.int,
) C.int {
	skBytes := C.GoBytes(unsafe.Pointer(skData), skLen)
	ctBytes := C.GoBytes(unsafe.Pointer(ctData), ctLen)

	priv, err := mlkem.PrivateKeyFromBytes(skBytes, mlkem.MLKEM768)
	if err != nil {
		return -1
	}

	sharedSecret, err := priv.Decapsulate(ctBytes)
	if err != nil {
		return -2
	}

	*ssLen = C.int(len(sharedSecret))
	C.memcpy(unsafe.Pointer(ss), unsafe.Pointer(&sharedSecret[0]), C.size_t(len(sharedSecret)))

	return 0
}

//export lux_mlkem768_pk_size
func lux_mlkem768_pk_size() C.int {
	return C.int(mlkem.MLKEM768PublicKeySize)
}

//export lux_mlkem768_sk_size
func lux_mlkem768_sk_size() C.int {
	return C.int(mlkem.MLKEM768PrivateKeySize)
}

//export lux_mlkem768_ct_size
func lux_mlkem768_ct_size() C.int {
	return C.int(mlkem.MLKEM768CiphertextSize)
}

// ═══════════════════════════════════════════════════════════════════════
// ML-DSA-65 (FIPS 204)
// ═══════════════════════════════════════════════════════════════════════

//export lux_mldsa65_keypair
func lux_mldsa65_keypair(pk *C.char, pkLen *C.int, sk *C.char, skLen *C.int) C.int {
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		return -1
	}

	pubBytes := priv.PublicKey.Bytes()
	privBytes := priv.Bytes()

	*pkLen = C.int(len(pubBytes))
	*skLen = C.int(len(privBytes))
	C.memcpy(unsafe.Pointer(pk), unsafe.Pointer(&pubBytes[0]), C.size_t(len(pubBytes)))
	C.memcpy(unsafe.Pointer(sk), unsafe.Pointer(&privBytes[0]), C.size_t(len(privBytes)))

	return 0
}

//export lux_mldsa65_sign
func lux_mldsa65_sign(
	skData *C.char, skLen C.int,
	msgData *C.char, msgLen C.int,
	sig *C.char, sigLen *C.int,
) C.int {
	skBytes := C.GoBytes(unsafe.Pointer(skData), skLen)
	msgBytes := C.GoBytes(unsafe.Pointer(msgData), msgLen)

	priv, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, skBytes)
	if err != nil {
		return -1
	}

	signature, err := priv.Sign(rand.Reader, msgBytes, nil)
	if err != nil {
		return -2
	}

	*sigLen = C.int(len(signature))
	C.memcpy(unsafe.Pointer(sig), unsafe.Pointer(&signature[0]), C.size_t(len(signature)))

	return 0
}

//export lux_mldsa65_verify
func lux_mldsa65_verify(
	pkData *C.char, pkLen C.int,
	msgData *C.char, msgLen C.int,
	sigData *C.char, sigLen C.int,
) C.int {
	pkBytes := C.GoBytes(unsafe.Pointer(pkData), pkLen)
	msgBytes := C.GoBytes(unsafe.Pointer(msgData), msgLen)
	sigBytes := C.GoBytes(unsafe.Pointer(sigData), sigLen)

	pub, err := mldsa.PublicKeyFromBytes(pkBytes, mldsa.MLDSA65)
	if err != nil {
		return -1
	}

	if pub.VerifySignature(msgBytes, sigBytes) {
		return 0
	}
	return -2
}

//export lux_mldsa65_pk_size
func lux_mldsa65_pk_size() C.int {
	return C.int(mldsa.MLDSA65PublicKeySize)
}

//export lux_mldsa65_sk_size
func lux_mldsa65_sk_size() C.int {
	return C.int(mldsa.MLDSA65PrivateKeySize)
}

//export lux_mldsa65_sig_size
func lux_mldsa65_sig_size() C.int {
	return C.int(mldsa.MLDSA65SignatureSize)
}

func main() {}
