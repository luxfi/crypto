// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bls

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// TestSignatureFromBytes_RejectsNonG2_PuregoParity is the regression test for
// the purego (CIRCL, //go:build !cgo) SignatureFromBytes point-validation fix.
//
// BEFORE the fix, the purego path accepted ANY length-96 input that had at
// least one non-zero byte — it performed NO on-curve and NO subgroup check,
// storing the raw bytes as a "Signature". That diverged from the CGO/blst path
// (Uncompress + SigValidate(false), which rejects non-G2 points) and admitted
// garbage signatures into the verifier.
//
// AFTER the fix, SignatureFromBytes parses the input through
// bls12381.G2.SetBytes, which decodes the compressed point and then calls
// IsOnG2() — isValidProjective() && isOnCurve() && isRTorsion() — before
// returning (CIRCL v1.6.3 ecc/bls12381/g2.go:86). isRTorsion() is the
// prime-order r-torsion SUBGROUP check (Bowe, eprint 2019/814), so SetBytes is
// the exact analogue of blst's SigValidate(false): on-curve AND in-subgroup.
//
// CIRCL provides no public API to MINT an on-curve-but-not-in-subgroup G2 point
// (Hash/Encode both clear the cofactor; SetBytes only admits subgroup points),
// so the subgroup leg cannot be exercised by feeding such a point — it is
// verified by construction in the library and by source review. This test pins
// the BEHAVIORAL change the fix makes: a structurally-invalid non-zero blob
// that the old byte-loop ACCEPTED is now REJECTED, while real signatures still
// round-trip and the all-zero input stays rejected.
func TestSignatureFromBytes_RejectsNonG2_PuregoParity(t *testing.T) {
	// 1) A real signature MUST still deserialize and round-trip unchanged.
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}
	realSig, err := sk.Sign([]byte("lux/chain/vote/v1"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	realBytes := SignatureToBytes(realSig)
	got, err := SignatureFromBytes(realBytes)
	if err != nil {
		t.Fatalf("SignatureFromBytes(real) rejected a valid signature: %v", err)
	}
	if !bytes.Equal(SignatureToBytes(got), realBytes) {
		t.Fatal("valid signature did not round-trip through SignatureFromBytes")
	}
	// Sanity: the real bytes are a valid G2 subgroup element (what SetBytes admits).
	var realPt bls12381.G2
	if err := realPt.SetBytes(realBytes); err != nil {
		t.Fatalf("real signature bytes are not a valid G2 point: %v", err)
	}
	if !realPt.IsOnG2() {
		t.Fatal("real signature point failed IsOnG2 (on-curve + r-torsion) sanity check")
	}

	// 2) The exact blob the OLD purego loop accepted (length 96, non-zero) but
	//    that is NOT a valid G2 encoding MUST now be rejected. byte[0]=0x01 has
	//    the compression bit clear, so SetBytes takes the uncompressed path and
	//    rejects on length (96 < 192). Deterministic. Without the fix this blob
	//    deserialized to a "Signature" — a garbage-signature forgery vector.
	garbage := make([]byte, SignatureLen)
	for i := range garbage {
		garbage[i] = byte(i + 1)
	}
	// Prove the premise: a non-G2 blob the old code would have waved through.
	var probe bls12381.G2
	if probe.SetBytes(garbage) == nil {
		t.Fatal("test premise broken: garbage blob unexpectedly decodes as a valid G2 point")
	}
	if _, err := SignatureFromBytes(garbage); err == nil {
		t.Fatal("SignatureFromBytes accepted a non-G2 garbage blob (no point validation — the bug)")
	}

	// 3) An input whose top-byte carries an INVALID encoding prefix (0x20/0x60/
	//    0xE0 per the BLS12-381 ZCash serialization) must be rejected outright.
	badPrefix := make([]byte, SignatureLen)
	badPrefix[0] = 0x20 // reserved/invalid compression-flag combination
	badPrefix[1] = 0x42 // ensure non-zero so this is distinct from the all-zero case
	if _, err := SignatureFromBytes(badPrefix); err == nil {
		t.Fatal("SignatureFromBytes accepted an input with an invalid G2 serialization prefix")
	}

	// 4) Preserved behavior: all-zero input is still rejected (it is not a valid
	//    non-infinity encoding, and not the canonical compressed-infinity form).
	if _, err := SignatureFromBytes(make([]byte, SignatureLen)); err == nil {
		t.Fatal("SignatureFromBytes accepted an all-zero input")
	}

	// 5) Preserved behavior: wrong length is rejected before any point parse.
	if _, err := SignatureFromBytes(make([]byte, SignatureLen-1)); err == nil {
		t.Fatal("SignatureFromBytes accepted a wrong-length input")
	}
}
