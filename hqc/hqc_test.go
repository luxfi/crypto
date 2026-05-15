// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"crypto/rand"
	"errors"
	"testing"
)

// TestParams_FixedSizes pins the NIST IR 8528 §4.1 wire-format sizes
// for HQC-128/192/256. These constants are part of the public API and
// must not drift across backend wirings.
func TestParams_FixedSizes(t *testing.T) {
	cases := []struct {
		mode    Mode
		pk, sk  int
		ct, ss  int
		secBits int
	}{
		{HQC128, 2249, 2305, 4481, 64, 128},
		{HQC192, 4522, 4586, 9026, 64, 192},
		{HQC256, 7245, 7317, 14469, 64, 256},
	}
	for _, c := range cases {
		p := MustParamsFor(c.mode)
		if p.PublicKeySize != c.pk {
			t.Errorf("HQC%d PublicKeySize=%d, want %d", c.secBits, p.PublicKeySize, c.pk)
		}
		if p.PrivateKeySize != c.sk {
			t.Errorf("HQC%d PrivateKeySize=%d, want %d", c.secBits, p.PrivateKeySize, c.sk)
		}
		if p.CiphertextSize != c.ct {
			t.Errorf("HQC%d CiphertextSize=%d, want %d", c.secBits, p.CiphertextSize, c.ct)
		}
		if p.SharedSecretSize != c.ss {
			t.Errorf("HQC%d SharedSecretSize=%d, want %d", c.secBits, p.SharedSecretSize, c.ss)
		}
	}
}

// TestBackend_StubReturnsErrBackendNotWired confirms the default
// (no-backend-tag) build cleanly surfaces ErrBackendNotWired rather
// than silently returning garbage or nil-derefing.
func TestBackend_StubReturnsErrBackendNotWired(t *testing.T) {
	_, err := KeyGen(HQC128, rand.Reader)
	if !errors.Is(err, ErrBackendNotWired) {
		t.Fatalf("KeyGen with no backend: want ErrBackendNotWired, got %v", err)
	}

	_, _, err = Encapsulate(&PublicKey{Mode: HQC128, Bytes: make([]byte, 2249)}, rand.Reader)
	if !errors.Is(err, ErrBackendNotWired) {
		t.Fatalf("Encapsulate with no backend: want ErrBackendNotWired, got %v", err)
	}

	_, err = Decapsulate(
		&PrivateKey{Mode: HQC128, Bytes: make([]byte, 2305)},
		&Ciphertext{Mode: HQC128, Bytes: make([]byte, 4481)},
	)
	if !errors.Is(err, ErrBackendNotWired) {
		t.Fatalf("Decapsulate with no backend: want ErrBackendNotWired, got %v", err)
	}
}

// TestDecapsulate_ModeMismatch — a ciphertext from one parameter set
// fed to a private key for another must return ErrModeMismatch, not
// silently produce a bogus shared secret.
func TestDecapsulate_ModeMismatch(t *testing.T) {
	_, err := Decapsulate(
		&PrivateKey{Mode: HQC128, Bytes: make([]byte, 2305)},
		&Ciphertext{Mode: HQC256, Bytes: make([]byte, 14469)},
	)
	if !errors.Is(err, ErrModeMismatch) {
		t.Errorf("mode mismatch: want ErrModeMismatch, got %v", err)
	}
}
