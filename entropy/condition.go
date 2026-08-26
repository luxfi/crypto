// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package entropy

import (
	"io"

	"golang.org/x/crypto/sha3"
)

// conditionTag separates conditioning from combining. Both use SHAKE256 over
// source bytes, and without distinct tags a conditioned draw and a combined
// one could coincide.
const conditionTag = "LUX-ENTROPY-CONDITION-V1"

// condition turns raw samples into a uniform stream.
//
// A physical source is biased and correlated even in good health — a diode
// runs slightly warm on one side, a detector favours an arm, samples adjacent
// in time are not independent. Conditioning removes that structure. It does
// not create entropy: the output carries what the input carried, spread evenly
// instead of unevenly, which is why the caller must supply more raw bytes than
// it takes out.
func condition(raw []byte) io.Reader {
	h := sha3.NewShake256()
	h.Write([]byte(conditionTag))
	h.Write(raw)
	return h
}
