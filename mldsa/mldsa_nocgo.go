// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
//go:build !cgo
// +build !cgo

// Package mldsa provides ML-DSA (FIPS 204) post-quantum signatures
// Pure Go implementation using Cloudflare's CIRCL library

package mldsa

import (
	"crypto"
	"io"
)

// UseCGO returns false when CGO is not available
func UseCGO() bool {
	return false
}

// GenerateKeyCGO falls back to pure Go implementation when CGO is disabled
func GenerateKeyCGO(rand io.Reader, mode Mode) (*PrivateKey, error) {
	return GenerateKey(rand, mode)
}

// SignCGO falls back to pure Go implementation when CGO is disabled
func SignCGO(priv *PrivateKey, rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.Sign(rand, message, opts)
}

// VerifyCGO falls back to pure Go implementation when CGO is disabled
func VerifyCGO(pub *PublicKey, message, signature []byte) bool {
	return pub.Verify(message, signature)
}
