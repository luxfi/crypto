// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bls

import "testing"

// TestBLS_HIGH1_InfinityBitSet_CompressionClear is the regression guard for the
// purego (CIRCL, //go:build !cgo) unauthenticated panic-DoS (HIGH-1).
//
// CIRCL's bls12381 G1/G2 SetBytes accepts the MALFORMED encoding where the
// infinity bit (0x40) is set but the compression bit (0x80) is CLEAR — top byte
// b[0]&0xC0 == 0x40. In that branch it computes the UNCOMPRESSED length
// (G1Size=96 / G2Size=192) and slices b[1:l] on what is actually a CANONICAL
// compressed buffer (PublicKeyLen=48 / SignatureLen=96):
//
//	ecc/bls12381/g1.go: if isInfinity==1 { l := G1Size; ... b[1:l] ... }  // l=96 on a 48-byte buf
//	ecc/bls12381/g2.go: if isInfinity==1 { l := G2Size; ... b[1:l] ... }  // l=192 on a 96-byte buf
//
// → "slice bounds out of range" runtime PANIC. The canonical node image is
// CGO_ENABLED=0 (purego), so a single `0x40 || zeros` blob in a proof-of-
// possession, peer-handshake, or warp/quasar BLS field CRASHES every node — an
// unauthenticated, consensus-halting DoS.
//
// The fix rejects b[0]&0xC0 == 0x40 at the compressed length BEFORE SetBytes,
// as an in-band error (NOT a recover()): a precise input rejection that matches
// the CGO/blst path (whose Uncompress returns an error, never panics). This test
// asserts NO PANIC and a clean error for the exact attack input at both lengths.
func TestBLS_HIGH1_InfinityBitSet_CompressionClear(t *testing.T) {
	// G1 / public key: 0x40 || zeros at the canonical compressed length (48).
	t.Run("PublicKeyFromCompressedBytes/G1", func(t *testing.T) {
		b := make([]byte, PublicKeyLen)
		b[0] = 0x40 // infinity bit set, compression bit clear
		// MUST NOT panic; MUST return a clean decompress error.
		pk, err := PublicKeyFromCompressedBytes(b)
		if err == nil {
			t.Fatal("PublicKeyFromCompressedBytes accepted 0x40||zeros (must reject)")
		}
		if pk != nil {
			t.Fatal("PublicKeyFromCompressedBytes returned a non-nil key for a rejected input")
		}
	})

	// G2 / signature: 0x40 || zeros at the canonical compressed length (96).
	t.Run("SignatureFromBytes/G2", func(t *testing.T) {
		b := make([]byte, SignatureLen)
		b[0] = 0x40
		sig, err := SignatureFromBytes(b)
		if err == nil {
			t.Fatal("SignatureFromBytes accepted 0x40||zeros (must reject)")
		}
		if sig != nil {
			t.Fatal("SignatureFromBytes returned a non-nil signature for a rejected input")
		}
	})

	// The reject must be on the (infinity-set, compression-clear) bit pattern,
	// independent of the trailing bytes — a single high byte is enough to brick a
	// node, with or without payload after it. Non-zero tail must ALSO be rejected
	// (and must not panic).
	t.Run("PublicKey/G1/nonzero-tail", func(t *testing.T) {
		b := make([]byte, PublicKeyLen)
		b[0] = 0x40
		b[1] = 0xFF
		if _, err := PublicKeyFromCompressedBytes(b); err == nil {
			t.Fatal("PublicKeyFromCompressedBytes accepted 0x40 with non-zero tail")
		}
	})
	t.Run("Signature/G2/nonzero-tail", func(t *testing.T) {
		b := make([]byte, SignatureLen)
		b[0] = 0x40
		b[1] = 0xFF
		if _, err := SignatureFromBytes(b); err == nil {
			t.Fatal("SignatureFromBytes accepted 0x40 with non-zero tail")
		}
	})

	// The full malformed-infinity family (compression clear, infinity set, any of
	// the low 5 flag/sign bits) must be rejected at both lengths without panic.
	// These are exactly the b[0] values that drove CIRCL into the uncompressed-
	// length branch on a compressed buffer.
	t.Run("flag-family/no-panic", func(t *testing.T) {
		for _, hi := range []byte{0x40, 0x41, 0x50, 0x60, 0x7F} {
			pkb := make([]byte, PublicKeyLen)
			pkb[0] = hi
			if _, err := PublicKeyFromCompressedBytes(pkb); err == nil {
				t.Fatalf("PublicKeyFromCompressedBytes accepted malformed prefix 0x%02x", hi)
			}
			sgb := make([]byte, SignatureLen)
			sgb[0] = hi
			if _, err := SignatureFromBytes(sgb); err == nil {
				t.Fatalf("SignatureFromBytes accepted malformed prefix 0x%02x", hi)
			}
		}
	})
}

// TestBLS_HIGH1_CanonicalInfinityStillRejected pins that the fix does NOT change
// the handling of the CANONICAL compressed-infinity encoding (0xc0 || zeros):
// it remains rejected (identity is not a valid public key / signature), via the
// existing Validate()/IsIdentity() guards — the HIGH-1 length-prefix guard only
// targets the malformed (compression-clear) infinity form, leaving the canonical
// form to the identity checks. This proves the guard is additive, not a
// replacement that could let the canonical identity slip through.
func TestBLS_HIGH1_CanonicalInfinityStillRejected(t *testing.T) {
	// 0xc0 = compression bit + infinity bit set (the canonical compressed
	// point-at-infinity per the ZCash BLS12-381 serialization).
	pkInf := make([]byte, PublicKeyLen)
	pkInf[0] = 0xc0
	if _, err := PublicKeyFromCompressedBytes(pkInf); err == nil {
		t.Fatal("PublicKeyFromCompressedBytes accepted the canonical identity (0xc0||zeros)")
	}
	sigInf := make([]byte, SignatureLen)
	sigInf[0] = 0xc0
	if _, err := SignatureFromBytes(sigInf); err == nil {
		t.Fatal("SignatureFromBytes accepted the canonical identity (0xc0||zeros)")
	}
}
