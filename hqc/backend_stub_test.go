// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !hqc_circl && !hqc_pqclean

package hqc

import (
	"crypto/rand"
	"errors"
	"testing"
)

// TestBackend_StubReturnsErrBackendNotWired confirms the default
// (no-backend-tag) build cleanly surfaces ErrBackendNotWired rather
// than silently returning garbage or nil-derefing.
//
// Lives in a build-tag-gated test file so it does NOT run when a
// real backend (hqc_pqclean / hqc_circl) is wired in.
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
		&Ciphertext{Mode: HQC128, Bytes: make([]byte, 4433)},
	)
	if !errors.Is(err, ErrBackendNotWired) {
		t.Fatalf("Decapsulate with no backend: want ErrBackendNotWired, got %v", err)
	}
}
