// Package main exports lux/crypto PQ functions as a C shared library.
//
// Build it with `make dist`, which is the only recipe: on macOS the library
// has to be named @rpath/libluxcrypto.dylib or no consumer can say where it
// is, and a build spelled out by hand gets that wrong every time.
//
// This produces libluxcrypto.{so,dylib,dll} + libluxcrypto.h
// which Python (ctypes/cffi), TypeScript (N-API/WASM), and Rust (FFI) can bind to.
//
// Symbols are brand-neutral (algorithm-namespaced); the brand is in the
// library file name only.
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

//export mlkem768_keypair
func mlkem768_keypair(pk *C.char, pkLen *C.int, sk *C.char, skLen *C.int) C.int {
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

//export mlkem768_encapsulate
func mlkem768_encapsulate(
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

//export mlkem768_decapsulate
func mlkem768_decapsulate(
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

//export mlkem768_pk_size
func mlkem768_pk_size() C.int {
	return C.int(mlkem.MLKEM768PublicKeySize)
}

//export mlkem768_sk_size
func mlkem768_sk_size() C.int {
	return C.int(mlkem.MLKEM768PrivateKeySize)
}

//export mlkem768_ct_size
func mlkem768_ct_size() C.int {
	return C.int(mlkem.MLKEM768CiphertextSize)
}

// ═══════════════════════════════════════════════════════════════════════
// ML-DSA-65 (FIPS 204)
// ═══════════════════════════════════════════════════════════════════════

//export mldsa65_keypair
func mldsa65_keypair(pk *C.char, pkLen *C.int, sk *C.char, skLen *C.int) C.int {
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

//export mldsa65_sign
func mldsa65_sign(
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

//export mldsa65_verify
func mldsa65_verify(
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

// The context-taking pair. FIPS 204 signs over a context string as well as the
// message, and a signature made under one context does not verify under
// another — which is what lets one key sign for two protocols without either
// signature being replayable into the other. The context-free calls above pass
// no context and are not the same operation.
//
// The C++ node's post-quantum handshake calls these two by name and could not
// link without them, so it was never added to its build at all.

//export mldsa65_sign_ctx
func mldsa65_sign_ctx(
	skData *C.char, skLen C.int,
	msgData *C.char, msgLen C.int,
	ctxData *C.char, ctxLen C.int,
	sig *C.char, sigLen *C.int,
) C.int {
	skBytes := C.GoBytes(unsafe.Pointer(skData), skLen)
	msgBytes := C.GoBytes(unsafe.Pointer(msgData), msgLen)
	ctxBytes := C.GoBytes(unsafe.Pointer(ctxData), ctxLen)

	priv, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, skBytes)
	if err != nil {
		return -1
	}

	signature, err := priv.SignCtx(rand.Reader, msgBytes, ctxBytes)
	if err != nil {
		return -2
	}

	*sigLen = C.int(len(signature))
	C.memcpy(unsafe.Pointer(sig), unsafe.Pointer(&signature[0]), C.size_t(len(signature)))

	return 0
}

//export mldsa65_verify_ctx
func mldsa65_verify_ctx(
	pkData *C.char, pkLen C.int,
	msgData *C.char, msgLen C.int,
	ctxData *C.char, ctxLen C.int,
	sigData *C.char, sigLen C.int,
) C.int {
	pkBytes := C.GoBytes(unsafe.Pointer(pkData), pkLen)
	msgBytes := C.GoBytes(unsafe.Pointer(msgData), msgLen)
	ctxBytes := C.GoBytes(unsafe.Pointer(ctxData), ctxLen)
	sigBytes := C.GoBytes(unsafe.Pointer(sigData), sigLen)

	pub, err := mldsa.PublicKeyFromBytes(pkBytes, mldsa.MLDSA65)
	if err != nil {
		return -1
	}

	if pub.VerifySignatureCtx(msgBytes, sigBytes, ctxBytes) {
		return 0
	}
	return -2
}

//export mldsa65_pk_size
func mldsa65_pk_size() C.int {
	return C.int(mldsa.MLDSA65PublicKeySize)
}

//export mldsa65_sk_size
func mldsa65_sk_size() C.int {
	return C.int(mldsa.MLDSA65PrivateKeySize)
}

//export mldsa65_sig_size
func mldsa65_sig_size() C.int {
	return C.int(mldsa.MLDSA65SignatureSize)
}

func main() {}
