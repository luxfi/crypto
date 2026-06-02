// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build hqc_pqclean

// backend_pqclean.go — cgo binding to the vendored PQClean HQC
// reference implementation (crypto/hqc/pqclean/, public domain).
//
// PQClean ships three independent build sets under
// crypto_kem/hqc-{128,192,256}/clean/. Each set uses namespaced
// functions (PQCLEAN_HQC128_CLEAN_*, etc.) so all three can coexist
// in one Go binary. The per-mode amalgamators hqcN_amalg.c bundle the
// 12 source files of each mode into one translation unit. fips202.c
// is shared across all three (unnamespaced symbols) and lives in its
// own TU — fips202_amalg.c.
//
// PQClean's HQC API takes its randomness from a `randombytes` symbol
// the linker resolves at build time. We provide randombytes_shim.c,
// which forwards to a Go callback (hqcGoRandombytes below). For each
// cgo entry we install a goroutine-local io.Reader (via a global
// guarded by a mutex — HQC operations are not internally parallel so
// the lock is taken for the duration of one keygen/encap/decap call).
//
// Determinism contract: each cgo call consumes EXACTLY the bytes that
// PQClean's HQC reference would consume for that operation. Replaying
// the same `(seed, op)` produces byte-identical outputs. This is
// load-bearing for the on-chain HQC precompile (validators must reach
// consensus on encapsulation outputs).
package hqc

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/pqclean/common -O2 -std=c99 -Wno-unused-function -Wno-unused-variable

#include <stdint.h>
#include <stddef.h>

// HQC-128
extern int PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQC128_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQC128_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// HQC-192
extern int PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQC192_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQC192_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// HQC-256
extern int PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQC256_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQC256_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
*/
import "C"

import (
	"errors"
	"io"
	"sync"
	"unsafe"
)

// rngState pairs an io.Reader with a sticky read error so that a
// partial read midway through a cgo call is surfaced once the call
// returns. PQClean's HQC reference does not propagate randombytes
// failures; we capture them on the Go side and report after.
type rngState struct {
	reader io.Reader
	err    error
}

var (
	rngMu     sync.Mutex
	activeRNG *rngState
)

// installRNG takes the cgo lock and registers `r` as the entropy
// source consumed by PQClean during the next call. The caller must
// invoke clearRNG (typically via defer) before returning.
func installRNG(r io.Reader) {
	rngMu.Lock()
	activeRNG = &rngState{reader: r}
}

// clearRNG releases the cgo lock and returns the sticky read error,
// if any.
func clearRNG() error {
	s := activeRNG
	activeRNG = nil
	rngMu.Unlock()
	if s == nil {
		return nil
	}
	return s.err
}

// Called from randombytes_shim.c. Reads exactly `n` bytes from the
// installed RNG into the buffer at `buf`. Returns 0 on full read,
// non-zero on partial read or reader error (PQClean checks the
// return value of randombytes() == 0).
//
//export hqcGoRandombytes
func hqcGoRandombytes(buf *C.uint8_t, n C.size_t) C.int {
	if activeRNG == nil {
		// Misuse — no RNG installed. Fail loudly via non-zero return
		// rather than silently zero-fill (which would produce a
		// deterministic-but-attacker-controllable keypair).
		return C.int(-1)
	}
	if n == 0 {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	_, err := io.ReadFull(activeRNG.reader, dst)
	if err != nil {
		activeRNG.err = err
		return C.int(-1)
	}
	return 0
}

// errRNGFailed surfaces a randombytes shortfall back to the caller.
var errRNGFailed = errors.New("hqc: PQClean randombytes read failed (underlying reader returned error or short read)")

func backendKeyGen(mode Mode, rng io.Reader) (*PrivateKey, error) {
	if rng == nil {
		return nil, errors.New("hqc: nil rng")
	}
	params := MustParamsFor(mode)
	pk := make([]byte, params.PublicKeySize)
	sk := make([]byte, params.PrivateKeySize)

	installRNG(rng)
	var rc C.int
	switch mode {
	case HQC128:
		rc = C.PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(
			(*C.uint8_t)(unsafe.Pointer(&pk[0])),
			(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		)
	case HQC192:
		rc = C.PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(
			(*C.uint8_t)(unsafe.Pointer(&pk[0])),
			(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		)
	case HQC256:
		rc = C.PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(
			(*C.uint8_t)(unsafe.Pointer(&pk[0])),
			(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		)
	default:
		clearRNG()
		return nil, ErrModeMismatch
	}
	rngErr := clearRNG()
	if rngErr != nil {
		return nil, rngErr
	}
	if rc != 0 {
		return nil, errRNGFailed
	}
	return &PrivateKey{
		Mode:  mode,
		Bytes: sk,
		Pub:   &PublicKey{Mode: mode, Bytes: pk},
	}, nil
}

func backendEncapsulate(pk *PublicKey, rng io.Reader) (*Ciphertext, []byte, error) {
	if rng == nil {
		return nil, nil, errors.New("hqc: nil rng")
	}
	params := MustParamsFor(pk.Mode)
	if len(pk.Bytes) != params.PublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}
	ct := make([]byte, params.CiphertextSize)
	ss := make([]byte, params.SharedSecretSize)

	installRNG(rng)
	var rc C.int
	switch pk.Mode {
	case HQC128:
		rc = C.PQCLEAN_HQC128_CLEAN_crypto_kem_enc(
			(*C.uint8_t)(unsafe.Pointer(&ct[0])),
			(*C.uint8_t)(unsafe.Pointer(&ss[0])),
			(*C.uint8_t)(unsafe.Pointer(&pk.Bytes[0])),
		)
	case HQC192:
		rc = C.PQCLEAN_HQC192_CLEAN_crypto_kem_enc(
			(*C.uint8_t)(unsafe.Pointer(&ct[0])),
			(*C.uint8_t)(unsafe.Pointer(&ss[0])),
			(*C.uint8_t)(unsafe.Pointer(&pk.Bytes[0])),
		)
	case HQC256:
		rc = C.PQCLEAN_HQC256_CLEAN_crypto_kem_enc(
			(*C.uint8_t)(unsafe.Pointer(&ct[0])),
			(*C.uint8_t)(unsafe.Pointer(&ss[0])),
			(*C.uint8_t)(unsafe.Pointer(&pk.Bytes[0])),
		)
	default:
		clearRNG()
		return nil, nil, ErrModeMismatch
	}
	rngErr := clearRNG()
	if rngErr != nil {
		return nil, nil, rngErr
	}
	if rc != 0 {
		return nil, nil, errRNGFailed
	}
	return &Ciphertext{Mode: pk.Mode, Bytes: ct}, ss, nil
}

func backendDecapsulate(sk *PrivateKey, ct *Ciphertext) ([]byte, error) {
	params := MustParamsFor(sk.Mode)
	if len(sk.Bytes) != params.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	if len(ct.Bytes) != params.CiphertextSize {
		return nil, ErrInvalidCiphertext
	}
	ss := make([]byte, params.SharedSecretSize)

	// Decapsulation does not consume entropy — HQC's decap is
	// deterministic given (sk, ct). We still take the cgo lock so that
	// the global `activeRNG` slot is well-defined if any future
	// PQClean revision adds an entropy call to decap.
	rngMu.Lock()
	var rc C.int
	switch sk.Mode {
	case HQC128:
		rc = C.PQCLEAN_HQC128_CLEAN_crypto_kem_dec(
			(*C.uint8_t)(unsafe.Pointer(&ss[0])),
			(*C.uint8_t)(unsafe.Pointer(&ct.Bytes[0])),
			(*C.uint8_t)(unsafe.Pointer(&sk.Bytes[0])),
		)
	case HQC192:
		rc = C.PQCLEAN_HQC192_CLEAN_crypto_kem_dec(
			(*C.uint8_t)(unsafe.Pointer(&ss[0])),
			(*C.uint8_t)(unsafe.Pointer(&ct.Bytes[0])),
			(*C.uint8_t)(unsafe.Pointer(&sk.Bytes[0])),
		)
	case HQC256:
		rc = C.PQCLEAN_HQC256_CLEAN_crypto_kem_dec(
			(*C.uint8_t)(unsafe.Pointer(&ss[0])),
			(*C.uint8_t)(unsafe.Pointer(&ct.Bytes[0])),
			(*C.uint8_t)(unsafe.Pointer(&sk.Bytes[0])),
		)
	default:
		rngMu.Unlock()
		return nil, ErrModeMismatch
	}
	rngMu.Unlock()
	// rc != 0 indicates HQC implicit rejection (the FO-transform's
	// re-encryption did not match). PQClean still returns a 64-byte
	// `ss` derived from the secret key + ciphertext — this is the
	// Hofheinz-Hövelmanns-Kiltz construction, where decap of a tampered
	// ciphertext yields a pseudorandom secret rather than an error.
	// Do not surface as a Go error; let callers compare.
	_ = rc
	return ss, nil
}
