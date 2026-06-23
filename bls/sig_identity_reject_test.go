// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// sig_identity_reject_test.go — INFO-4 regression: SignatureFromBytes must reject
// the G2 identity (point at infinity), symmetric with the pubkey identity guard.
// The pubkey side rejects identity at the deserialization boundary
// (PublicKeyFrom*Bytes → Validate()/KeyValidate()), so this pins the matching
// signature-side reject. The canonical compressed G2 identity is 0xc0 || 95 zero bytes
// (compression bit + infinity bit set; all coordinate bytes zero — see blst
// e1.c:205 "compressed and infinity bits"). It is a WELL-FORMED encoding that
// both deserializers used to accept:
//   - purego (CIRCL): G2.SetBytes returns at the isInfinity branch BEFORE IsOnG2.
//   - blst: SigValidate(false) skipped the infinity check.
// The fix rejects it on both paths (purego: explicit IsIdentity reject; blst:
// SigValidate(true) does is_inf + in_g2). This test is build-tag agnostic so it
// runs against whichever implementation is compiled in, asserting BOTH paths
// behave identically.
package bls

import (
	"bytes"
	"testing"
)

// compressedG2Identity is the canonical compressed encoding of the G2 point at
// infinity: 0xc0 (compression|infinity bits) followed by zeros for the whole
// SignatureLen-byte field. This is the exact blob INFO-4 was accepting.
func compressedG2Identity() []byte {
	b := make([]byte, SignatureLen)
	b[0] = 0xc0
	return b
}

func TestSignatureFromBytes_RejectsIdentity(t *testing.T) {
	// (1) The canonical compressed G2 identity MUST be rejected. Before the fix
	// this deserialized cleanly (purego: returned at the infinity branch; blst:
	// SigValidate(false) skipped the infinity check).
	if sig, err := SignatureFromBytes(compressedG2Identity()); err == nil {
		t.Fatalf("INFO-4: SignatureFromBytes accepted the G2 identity (point at infinity); "+
			"got sig=%v, want rejection", sig)
	}

	// (2) A REAL signature still round-trips and verifies — the identity reject
	// must not block valid signatures.
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}
	msg := []byte("info-4 identity reject — real sig must survive")
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigBytes := SignatureToBytes(sig)

	roundTripped, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("SignatureFromBytes rejected a VALID signature: %v", err)
	}
	if !bytes.Equal(SignatureToBytes(roundTripped), sigBytes) {
		t.Fatal("valid signature did not round-trip byte-identically through SignatureFromBytes")
	}
	if !Verify(sk.PublicKey(), roundTripped, msg) {
		t.Fatal("round-tripped valid signature failed to verify against its key+message")
	}

	// (3) A real signature is NOT the identity — sanity that the guard is precise
	// (it rejects only the degenerate point, not the first byte 0xc0 generically;
	// real compressed G2 sigs may legitimately have the compression bit set).
	if bytes.Equal(sigBytes, compressedG2Identity()) {
		t.Fatal("a real signature must never equal the G2 identity encoding")
	}
}
