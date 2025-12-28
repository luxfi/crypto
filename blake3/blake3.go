// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package blake3 provides BLAKE3 hashing.
//
// BLAKE3 is a tree-based cryptographic hash function defined by the BLAKE3
// team (https://github.com/BLAKE3-team/BLAKE3-spec). This package wraps
// github.com/zeebo/blake3, which is a pure-Go implementation that matches
// the upstream test vectors byte-for-byte.
//
// Three modes are exposed:
//   - Sum256:   plain hash, 32-byte output
//   - Keyed:    keyed hash (MAC) with a 32-byte key
//   - DeriveKey: KDF with a context string, 32-byte output
//
// XOF (extendable output) is exposed via Sum, which writes any number of
// bytes to the destination slice.
package blake3

import (
	"github.com/zeebo/blake3"
)

// Size is the default BLAKE3 output length in bytes.
const Size = 32

// KeySize is the BLAKE3 key length in bytes (keyed-hash and KDF modes).
const KeySize = 32

// Sum256 returns the 32-byte BLAKE3 hash of data.
func Sum256(data []byte) [Size]byte {
	var out [Size]byte
	h := blake3.New()
	_, _ = h.Write(data)
	h.Sum(out[:0])
	return out
}

// Sum writes len(out) bytes of BLAKE3 XOF output for data into out.
func Sum(out, data []byte) {
	h := blake3.New()
	_, _ = h.Write(data)
	d := h.Digest()
	_, _ = d.Read(out)
}

// Keyed returns the 32-byte BLAKE3 keyed hash of data with the given 32-byte key.
func Keyed(key [KeySize]byte, data []byte) [Size]byte {
	var out [Size]byte
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		// NewKeyed only fails on wrong key length; key is fixed-size so this
		// path is unreachable.
		panic(err)
	}
	_, _ = h.Write(data)
	h.Sum(out[:0])
	return out
}

// KeyedXOF writes len(out) bytes of BLAKE3 keyed-XOF output into out.
func KeyedXOF(out []byte, key [KeySize]byte, data []byte) {
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(data)
	d := h.Digest()
	_, _ = d.Read(out)
}

// DeriveKey returns the 32-byte BLAKE3 derived key for the given context
// string and key material.
func DeriveKey(context string, keyMaterial []byte) [Size]byte {
	var out [Size]byte
	blake3.DeriveKey(context, keyMaterial, out[:])
	return out
}

// DeriveKeyXOF writes len(out) bytes of BLAKE3 derived-key XOF into out.
func DeriveKeyXOF(out []byte, context string, keyMaterial []byte) {
	blake3.DeriveKey(context, keyMaterial, out)
}
