// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"testing"
	"time"
)

// A PrivateKey zeroes its secret on collection, so it must hold a buffer no one
// else holds. These tests pin that: what goes in is copied, what comes out is a
// copy, and collection touches neither.

// adopt parses data and yields the key's own secret buffer. The key is
// unreachable once this returns, so it may be collected while the returned
// slice keeps the array it zeroes observable.
func adopt(t *testing.T, mode Mode, data []byte) []byte {
	t.Helper()
	priv, err := PrivateKeyFromBytes(mode, data)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes: %v", err)
	}
	return priv.secretKey
}

func blank(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// awaitBlank collects until the key's own buffer is zeroed. Reaching this
// proves the finalizer ran, so a later "caller's buffer intact" assertion
// cannot pass merely because collection never happened.
func awaitBlank(t *testing.T, own []byte) {
	t.Helper()
	for i := 0; i < 200; i++ {
		runtime.GC()
		if blank(own) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("finalizer never ran: the key's own buffer was never zeroed")
}

func TestKeyFromBytesOwnsItsSecret(t *testing.T) {
	for _, mode := range []Mode{MLDSA44, MLDSA65, MLDSA87} {
		gen, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			t.Fatalf("mode %d: GenerateKey: %v", mode, err)
		}
		caller := bytes.Clone(gen.Bytes())
		runtime.KeepAlive(gen)
		want := bytes.Clone(caller)

		own := adopt(t, mode, caller)
		if &own[0] == &caller[0] {
			t.Fatalf("mode %d: key shares the caller's array", mode)
		}

		awaitBlank(t, own)

		if !bytes.Equal(caller, want) {
			t.Fatalf("mode %d: collecting the key zeroed the caller's slice", mode)
		}
	}
}

// TestBytesHandsBackACopy covers the other side of the boundary: an exported
// secret must survive the key it came from.
func TestBytesHandsBackACopy(t *testing.T) {
	for _, mode := range []Mode{MLDSA44, MLDSA65, MLDSA87} {
		var own, out []byte
		func() {
			priv, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				t.Fatalf("mode %d: GenerateKey: %v", mode, err)
			}
			out = priv.Bytes()
			own = priv.secretKey
		}()
		want := bytes.Clone(out)
		if &out[0] == &own[0] {
			t.Fatalf("mode %d: Bytes shares the key's array", mode)
		}

		awaitBlank(t, own)

		if !bytes.Equal(out, want) {
			t.Fatalf("mode %d: collecting the key zeroed the exported secret", mode)
		}
	}
}

// TestSignSurvivesCollection is the consequence in the shape production sees:
// a stored secret re-parsed per signature must keep producing valid signatures.
func TestSignSurvivesCollection(t *testing.T) {
	const mode = MLDSA65
	gen, err := GenerateKey(rand.Reader, mode)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	stored := bytes.Clone(gen.Bytes())
	pub := gen.PublicKey
	runtime.KeepAlive(gen)

	msg := []byte("validator stamp")
	sign := func() []byte {
		priv, err := PrivateKeyFromBytes(mode, stored)
		if err != nil {
			t.Fatalf("PrivateKeyFromBytes: %v", err)
		}
		sig, err := priv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return sig
	}

	if !pub.VerifySignature(msg, sign()) {
		t.Fatal("first signature did not verify")
	}
	for i := 0; i < 20; i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	}
	if !pub.VerifySignature(msg, sign()) {
		t.Fatal("signature made after collection did not verify")
	}
}
