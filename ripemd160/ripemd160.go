// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ripemd160

import (
	"hash"

	xripemd "golang.org/x/crypto/ripemd160" //nolint:gosec
)

// Size is the output size of RIPEMD-160 in bytes.
const Size = xripemd.Size

// Sum160 computes the RIPEMD-160 digest of in.
func Sum160(in []byte) [Size]byte {
	h := xripemd.New() //nolint:gosec
	h.Write(in)
	var out [Size]byte
	h.Sum(out[:0])
	return out
}

// New returns a new hash.Hash computing RIPEMD-160.
func New() hash.Hash { return xripemd.New() } //nolint:gosec
