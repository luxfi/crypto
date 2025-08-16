// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package blake3 provides Blake3 hash functions for cryptographic operations.
// This is extracted from the threshold package to provide a centralized
// implementation for all Lux projects.
package blake3

import (
	"encoding/binary"
	"io"
	"math/big"

	"github.com/zeebo/blake3"
)

// DigestLength is the standard output length for Blake3 hashes
const DigestLength = 64 // 512 bits

// Digest represents a Blake3 hash output
type Digest [DigestLength]byte

// Hasher wraps blake3.Hasher to provide a consistent interface
type Hasher struct {
	h *blake3.Hasher
}

// New creates a new Blake3 hasher
func New() *Hasher {
	return &Hasher{h: blake3.New()}
}

// NewWithDomain creates a new Blake3 hasher with a domain separator
func NewWithDomain(domain string) *Hasher {
	h := &Hasher{h: blake3.New()}
	h.WriteString(domain)
	return h
}

// Write adds data to the hash
func (h *Hasher) Write(p []byte) (n int, err error) {
	return h.h.Write(p)
}

// WriteString adds a string to the hash
func (h *Hasher) WriteString(s string) (n int, err error) {
	return h.h.WriteString(s)
}

// WriteUint32 adds a uint32 to the hash in big-endian format
func (h *Hasher) WriteUint32(v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	h.h.Write(buf[:])
}

// WriteUint64 adds a uint64 to the hash in big-endian format
func (h *Hasher) WriteUint64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	h.h.Write(buf[:])
}

// WriteBigInt adds a big.Int to the hash
func (h *Hasher) WriteBigInt(n *big.Int) {
	if n == nil {
		h.WriteUint32(0)
		return
	}
	bytes := n.Bytes()
	h.WriteUint32(uint32(len(bytes)))
	h.h.Write(bytes)
}

// Sum returns the hash digest
func (h *Hasher) Sum(b []byte) []byte {
	return h.h.Sum(b)
}

// Digest returns a fixed-size digest
func (h *Hasher) Digest() Digest {
	var d Digest
	h.h.Digest().Read(d[:])
	return d
}

// Reader returns an io.Reader for extended output
func (h *Hasher) Reader() io.Reader {
	return h.h.Digest()
}

// Clone creates a copy of the hasher
func (h *Hasher) Clone() *Hasher {
	return &Hasher{h: h.h.Clone()}
}

// Reset resets the hasher to its initial state
func (h *Hasher) Reset() {
	h.h.Reset()
}

// HashBytes hashes a byte slice and returns a digest
func HashBytes(data []byte) Digest {
	h := New()
	h.Write(data)
	return h.Digest()
}

// HashString hashes a string and returns a digest
func HashString(s string) Digest {
	h := New()
	h.WriteString(s)
	return h.Digest()
}

// HashWithDomain hashes data with a domain separator
func HashWithDomain(domain string, data []byte) Digest {
	h := NewWithDomain(domain)
	h.Write(data)
	return h.Digest()
}