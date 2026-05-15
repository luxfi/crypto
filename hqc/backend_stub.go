// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !hqc_circl && !hqc_pqclean

package hqc

import "io"

// backend_stub.go — default build (no HQC backend wired).
//
// Every entry point returns ErrBackendNotWired. Build with one of:
//   -tags=hqc_pqclean   cgo binding to PQClean's HQC reference C
//   -tags=hqc_circl     Cloudflare CIRCL Go implementation (when shipped)
//
// The stub keeps the package buildable on hosts where the backend
// libraries aren't installed (same discipline as luxfi/accel's weak-stub
// fallback for native GPU libs).

func backendKeyGen(_ Mode, _ io.Reader) (*PrivateKey, error) {
	return nil, ErrBackendNotWired
}

func backendEncapsulate(_ *PublicKey, _ io.Reader) (*Ciphertext, []byte, error) {
	return nil, nil, ErrBackendNotWired
}

func backendDecapsulate(_ *PrivateKey, _ *Ciphertext) ([]byte, error) {
	return nil, ErrBackendNotWired
}
