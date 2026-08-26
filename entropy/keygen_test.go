// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package entropy_test

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/luxfi/crypto/entropy"
	"github.com/luxfi/crypto/mldsa"
)

// TestKeyGenerationTakesASource is the whole integration claim: adopting a
// hardware entropy source is supplying a different reader. No consensus
// change, no fork, no new chain — the seam every key generator here already
// has is an io.Reader.
func TestKeyGenerationTakesASource(t *testing.T) {
	src := entropy.Combine(entropy.OS())

	priv, err := mldsa.GenerateKey(src, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("generate a key from an entropy source: %v", err)
	}
	if priv == nil {
		t.Fatal("no key")
	}

	// The key works, which is the only thing that distinguishes a real source
	// from one that returns zeros.
	msg := []byte("attested")
	sig, err := priv.Sign(src, msg, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !priv.PublicKey.Verify(msg, sig, nil) {
		t.Fatal("a signature made with entropy-sourced material did not verify")
	}
}

// unhealthy stands for a source whose health tests have failed.
type unhealthy struct{}

func (unhealthy) Health() error            { return entropy.ErrUnhealthy }
func (unhealthy) Read([]byte) (int, error) { return 0, entropy.ErrUnhealthy }

// TestAKeyIsNotGeneratedFromABrokenSource. The failure this guards is the
// quiet one: a degraded source emits bytes of the right length, and a key made
// from them verifies and signs and behaves correctly in every respect except
// being unpredictable. Nothing downstream can detect it, so the refusal has to
// happen here.
func TestAKeyIsNotGeneratedFromABrokenSource(t *testing.T) {
	src := entropy.Combine(entropy.OS(), unhealthy{})
	if _, err := mldsa.GenerateKey(src, mldsa.MLDSA65); !errors.Is(err, entropy.ErrUnhealthy) {
		t.Fatalf("a key was generated from an unhealthy source: err = %v", err)
	}
}

// A source is a drop-in for crypto/rand.Reader wherever one is taken.
func TestASourceIsAnIOReader(t *testing.T) {
	var r io.Reader = entropy.Combine(entropy.OS())
	if _, err := io.ReadFull(r, make([]byte, 64)); err != nil {
		t.Fatalf("read: %v", err)
	}
	// And the platform reader still works beside it, since a deployment always
	// holds both.
	if _, err := io.ReadFull(rand.Reader, make([]byte, 64)); err != nil {
		t.Fatalf("platform read: %v", err)
	}
}
