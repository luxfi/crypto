// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kats

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// TestKAT_MLDSA44 walks Vectors44 and asserts byte-equality on the
// derived public key, private key, and deterministic signature for
// every record. A failure here means the synthetic vector pin is
// stale — either the upstream CIRCL implementation moved (in which
// case we want to know before downstream consumers do) or the
// generator was run without committing its output.
func TestKAT_MLDSA44(t *testing.T) {
	if len(Vectors44) == 0 {
		t.Fatal("Vectors44 is empty — did you forget to run `make gen_kats`?")
	}
	for _, v := range Vectors44 {
		v := v
		t.Run(vectorName("mldsa44", v.Count), func(t *testing.T) {
			pk, sk, err := mldsa44.NewKeyFromSeed(v.Seed)
			if err != nil {
				t.Fatalf("count %d NewKeyFromSeed: %v", v.Count, err)
			}
			if !bytes.Equal(pk.Bytes(), v.PublicKey) {
				t.Fatalf("count %d: public key mismatch (got %d bytes, want %d)",
					v.Count, len(pk.Bytes()), len(v.PublicKey))
			}
			if !bytes.Equal(sk.Bytes(), v.PrivateKey) {
				t.Fatalf("count %d: private key mismatch", v.Count)
			}
			sig, err := mldsa44.Sign(sk, v.Msg, v.Ctx, false)
			if err != nil {
				t.Fatalf("count %d Sign: %v", v.Count, err)
			}
			if !bytes.Equal(sig, v.Signature) {
				t.Fatalf("count %d: signature mismatch", v.Count)
			}
			if !mldsa44.Verify(pk, v.Msg, v.Ctx, v.Signature) {
				t.Fatalf("count %d: pinned signature does not verify", v.Count)
			}
			// Bad signature MUST be rejected. Flip a bit in c~ (the
			// first byte of sig) which is always present.
			bad := append([]byte{}, v.Signature...)
			bad[0] ^= 0x01
			if mldsa44.Verify(pk, v.Msg, v.Ctx, bad) {
				t.Fatalf("count %d: tampered signature accepted", v.Count)
			}
		})
	}
}

// TestKAT_MLDSA65 is the Level 3 counterpart of TestKAT_MLDSA44.
func TestKAT_MLDSA65(t *testing.T) {
	if len(Vectors65) == 0 {
		t.Fatal("Vectors65 is empty — did you forget to run `make gen_kats`?")
	}
	for _, v := range Vectors65 {
		v := v
		t.Run(vectorName("mldsa65", v.Count), func(t *testing.T) {
			pk, sk, err := mldsa65.NewKeyFromSeed(v.Seed)
			if err != nil {
				t.Fatalf("count %d NewKeyFromSeed: %v", v.Count, err)
			}
			if !bytes.Equal(pk.Bytes(), v.PublicKey) {
				t.Fatalf("count %d: public key mismatch", v.Count)
			}
			if !bytes.Equal(sk.Bytes(), v.PrivateKey) {
				t.Fatalf("count %d: private key mismatch", v.Count)
			}
			sig, err := mldsa65.Sign(sk, v.Msg, v.Ctx, false)
			if err != nil {
				t.Fatalf("count %d Sign: %v", v.Count, err)
			}
			if !bytes.Equal(sig, v.Signature) {
				t.Fatalf("count %d: signature mismatch", v.Count)
			}
			if !mldsa65.Verify(pk, v.Msg, v.Ctx, v.Signature) {
				t.Fatalf("count %d: pinned signature does not verify", v.Count)
			}
			bad := append([]byte{}, v.Signature...)
			bad[0] ^= 0x01
			if mldsa65.Verify(pk, v.Msg, v.Ctx, bad) {
				t.Fatalf("count %d: tampered signature accepted", v.Count)
			}
		})
	}
}

// TestKAT_MLDSA87 is the Level 5 counterpart.
func TestKAT_MLDSA87(t *testing.T) {
	if len(Vectors87) == 0 {
		t.Fatal("Vectors87 is empty — did you forget to run `make gen_kats`?")
	}
	for _, v := range Vectors87 {
		v := v
		t.Run(vectorName("mldsa87", v.Count), func(t *testing.T) {
			pk, sk, err := mldsa87.NewKeyFromSeed(v.Seed)
			if err != nil {
				t.Fatalf("count %d NewKeyFromSeed: %v", v.Count, err)
			}
			if !bytes.Equal(pk.Bytes(), v.PublicKey) {
				t.Fatalf("count %d: public key mismatch", v.Count)
			}
			if !bytes.Equal(sk.Bytes(), v.PrivateKey) {
				t.Fatalf("count %d: private key mismatch", v.Count)
			}
			sig, err := mldsa87.Sign(sk, v.Msg, v.Ctx, false)
			if err != nil {
				t.Fatalf("count %d Sign: %v", v.Count, err)
			}
			if !bytes.Equal(sig, v.Signature) {
				t.Fatalf("count %d: signature mismatch", v.Count)
			}
			if !mldsa87.Verify(pk, v.Msg, v.Ctx, v.Signature) {
				t.Fatalf("count %d: pinned signature does not verify", v.Count)
			}
			bad := append([]byte{}, v.Signature...)
			bad[0] ^= 0x01
			if mldsa87.Verify(pk, v.Msg, v.Ctx, bad) {
				t.Fatalf("count %d: tampered signature accepted", v.Count)
			}
		})
	}
}

// TestKAT_RandomizedSignVerifies is the companion to the
// deterministic-sign tests above. It does NOT pin signature bytes
// (a randomized signature has fresh nonce material every call), but
// it asserts that the deterministic-keygen + randomized-sign path
// produces a signature that verifies under the pinned public key.
//
// The test covers all three parameter sets and one vector each.
func TestKAT_RandomizedSignVerifies(t *testing.T) {
	if len(Vectors44) > 0 {
		v := Vectors44[0]
		_, sk, err := mldsa44.NewKeyFromSeed(v.Seed)
		if err != nil {
			t.Fatalf("mldsa44 keygen: %v", err)
		}
		sig, err := mldsa44.Sign(sk, v.Msg, v.Ctx, true)
		if err != nil {
			t.Fatalf("mldsa44 randomized Sign: %v", err)
		}
		var pkBuf [mldsa44.PublicKeySize]byte
		copy(pkBuf[:], v.PublicKey)
		var pk mldsa44.PublicKey
		pk.Unpack(&pkBuf)
		if !mldsa44.Verify(&pk, v.Msg, v.Ctx, sig) {
			t.Fatal("mldsa44 randomized sig fails Verify under pinned pk")
		}
	}
	if len(Vectors65) > 0 {
		v := Vectors65[0]
		_, sk, err := mldsa65.NewKeyFromSeed(v.Seed)
		if err != nil {
			t.Fatalf("mldsa65 keygen: %v", err)
		}
		sig, err := mldsa65.Sign(sk, v.Msg, v.Ctx, true)
		if err != nil {
			t.Fatalf("mldsa65 randomized Sign: %v", err)
		}
		var pkBuf [mldsa65.PublicKeySize]byte
		copy(pkBuf[:], v.PublicKey)
		var pk mldsa65.PublicKey
		pk.Unpack(&pkBuf)
		if !mldsa65.Verify(&pk, v.Msg, v.Ctx, sig) {
			t.Fatal("mldsa65 randomized sig fails Verify under pinned pk")
		}
	}
	if len(Vectors87) > 0 {
		v := Vectors87[0]
		_, sk, err := mldsa87.NewKeyFromSeed(v.Seed)
		if err != nil {
			t.Fatalf("mldsa87 keygen: %v", err)
		}
		sig, err := mldsa87.Sign(sk, v.Msg, v.Ctx, true)
		if err != nil {
			t.Fatalf("mldsa87 randomized Sign: %v", err)
		}
		var pkBuf [mldsa87.PublicKeySize]byte
		copy(pkBuf[:], v.PublicKey)
		var pk mldsa87.PublicKey
		pk.Unpack(&pkBuf)
		if !mldsa87.Verify(&pk, v.Msg, v.Ctx, sig) {
			t.Fatal("mldsa87 randomized sig fails Verify under pinned pk")
		}
	}
}

// vectorName produces a stable sub-test name for `go test -run`
// filtering. The format is "<param>/count<NN>".
func vectorName(param string, count int) string {
	return param + "/count" + fmtInt(count)
}

func fmtInt(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	// Two-digit max: our specs slice is short and the count never
	// exceeds 99. If that changes, expand this helper.
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
