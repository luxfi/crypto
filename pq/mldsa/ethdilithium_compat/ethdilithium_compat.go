// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ethdilithium_compat

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
)

// PublicKeySize, PrivateKeySize, SignatureSize re-export the
// FIPS 204 ML-DSA-65 wire sizes. The signature byte layout is
// identical to FIPS 204 ML-DSA-65; only the message preprocessing
// differs.
const (
	// PublicKeySize is the ML-DSA-65 public key byte length.
	PublicKeySize = mldsa65.PublicKeySize
	// PrivateKeySize is the ML-DSA-65 private key byte length.
	PrivateKeySize = mldsa65.PrivateKeySize
	// SignatureSize is the ML-DSA-65 signature byte length.
	SignatureSize = mldsa65.SignatureSize
)

// domainTag is the Keccak-256 domain-separation prefix bound into
// the effective-message hash. It identifies the EthDilithium variant
// so a downstream verifier cannot mistake the resulting "effective
// message" for either a raw user message or a FIPS 204 signed
// payload.
//
// We pin the string here rather than parameterizing it; downstream
// EVM verifiers will hard-code the same constant, so making it
// configurable would invite drift.
var domainTag = []byte("LUX/EthDilithium/v1")

// Errors. They are returned, never panicked.
var (
	// ErrPublicKeySize is returned when pkBytes is not PublicKeySize.
	ErrPublicKeySize = errors.New("ethdilithium_compat: public key size mismatch")
	// ErrPrivateKeySize is returned when skBytes is not PrivateKeySize.
	ErrPrivateKeySize = errors.New("ethdilithium_compat: private key size mismatch")
	// ErrSignatureSize is returned when sig is not SignatureSize.
	ErrSignatureSize = errors.New("ethdilithium_compat: signature size mismatch")
	// ErrContextTooLong is returned when ctx exceeds 255 bytes,
	// matching the FIPS 204 §5.2 limit.
	ErrContextTooLong = errors.New("ethdilithium_compat: context exceeds 255 bytes")
)

// Sign produces an EthDilithium signature on (msg, ctx) under
// skBytes (a FIPS 204 ML-DSA-65 wire-format private key). The
// returned signature is byte-compatible with FIPS 204 ML-DSA-65 in
// length and encoding, but the payload it commits to is the
// Keccak-256 effective message rather than the raw input.
//
// Determinism: ctx is mixed into the Keccak preprocessing; the
// underlying ML-DSA-65 sign call uses randomized=false, so the
// output is fully deterministic for a given (sk, msg, ctx) tuple.
func Sign(skBytes, msg, ctx []byte) ([]byte, error) {
	if len(skBytes) != PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d, want %d",
			ErrPrivateKeySize, len(skBytes), PrivateKeySize)
	}
	if len(ctx) > 255 {
		return nil, ErrContextTooLong
	}
	var skBuf [PrivateKeySize]byte
	copy(skBuf[:], skBytes)
	var sk mldsa65.PrivateKey
	sk.Unpack(&skBuf)

	effMsg := keccakEffectiveMessage(msg, ctx)
	// We pass empty ctx into ML-DSA because our own ctx is already
	// bound into effMsg. Passing the same ctx twice would create
	// two independent domain-separation tags for the same input,
	// which is undesirable for verifier round-tripping.
	sig, err := mldsa65.Sign(&sk, effMsg[:], nil, false)
	if err != nil {
		return nil, fmt.Errorf("ethdilithium_compat sign: %w", err)
	}
	return sig, nil
}

// Verify reports whether sig is a valid EthDilithium signature on
// (msg, ctx) under pkBytes (a FIPS 204 ML-DSA-65 wire-format public
// key). It returns false on any size mismatch and on any malformed
// input — boundary defenses match the FIPS 204 verifier's contract.
func Verify(pkBytes, msg, ctx, sig []byte) bool {
	if len(pkBytes) != PublicKeySize {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}
	if len(ctx) > 255 {
		return false
	}
	var pkBuf [PublicKeySize]byte
	copy(pkBuf[:], pkBytes)
	var pk mldsa65.PublicKey
	pk.Unpack(&pkBuf)

	effMsg := keccakEffectiveMessage(msg, ctx)
	return mldsa65.Verify(&pk, effMsg[:], nil, sig)
}

// keccakEffectiveMessage builds the 32-byte effective message:
//
//	effMsg = Keccak256(domainTag ‖ uint8(len(ctx)) ‖ ctx ‖ msg)
//
// The length-prefix byte sits between domainTag and ctx so that no
// pair (ctx=A, msg=B), (ctx=A‖B, msg="") can produce the same input
// — the prefix byte makes the (ctx, msg) split unambiguous. This
// is the same length-prefix discipline used in FIPS 204 §5.2.
func keccakEffectiveMessage(msg, ctx []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(domainTag)
	_, _ = h.Write([]byte{byte(len(ctx))})
	if len(ctx) > 0 {
		_, _ = h.Write(ctx)
	}
	if len(msg) > 0 {
		_, _ = h.Write(msg)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
