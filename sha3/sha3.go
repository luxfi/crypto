// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sha3

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

// Size constants for fixed-output SHA3 variants.
const (
	Size224 = 28
	Size256 = 32
	Size384 = 48
	Size512 = 64
)

// Sum224 returns the SHA3-224 hash of in.
func Sum224(in []byte) [Size224]byte { return sha3.Sum224(in) }

// Sum256 returns the SHA3-256 hash of in.
func Sum256(in []byte) [Size256]byte { return sha3.Sum256(in) }

// Sum384 returns the SHA3-384 hash of in.
func Sum384(in []byte) [Size384]byte { return sha3.Sum384(in) }

// Sum512 returns the SHA3-512 hash of in.
func Sum512(in []byte) [Size512]byte { return sha3.Sum512(in) }

// New224 returns a new hash.Hash computing SHA3-224.
func New224() hash.Hash { return sha3.New224() }

// New256 returns a new hash.Hash computing SHA3-256.
func New256() hash.Hash { return sha3.New256() }

// New384 returns a new hash.Hash computing SHA3-384.
func New384() hash.Hash { return sha3.New384() }

// New512 returns a new hash.Hash computing SHA3-512.
func New512() hash.Hash { return sha3.New512() }

// ShakeSum128 produces an outputLen-byte SHAKE128 digest of data.
func ShakeSum128(out, data []byte) { sha3.ShakeSum128(out, data) }

// ShakeSum256 produces an outputLen-byte SHAKE256 digest of data.
func ShakeSum256(out, data []byte) { sha3.ShakeSum256(out, data) }
