// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package entropy

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

// combineTag separates this use of SHAKE256 from every other one in Lux. Two
// constructions that hash the same bytes for different purposes must not be
// able to produce the same output, or a value drawn for one becomes usable in
// the other.
const combineTag = "LUX-ENTROPY-COMBINE-V1"

// drawPerSource is how many bytes are taken from each source per read. It is
// the security parameter's worth: a source contributing at least this much
// unpredictability saturates the output.
const drawPerSource = 32

// Combine reads from every source and mixes what it gets.
//
// The mix is a hash of the concatenation, each contribution preceded by its
// length, under a tag used nowhere else:
//
//	SHAKE256( tag || LE64(len(s_1)) || s_1 || ... || LE64(len(s_n)) || s_n )
//
// Two properties follow, and both are the point rather than decoration.
//
// Adding a source cannot weaken the result. Predicting the output means
// predicting the hash input, which means predicting every contribution — so
// one unpredictable source is enough regardless of what the others do. This is
// what allows a new and unproven device to be added to a running deployment:
// at worst it contributes nothing, and it can never subtract.
//
// The lengths keep the contributions distinct. Concatenated raw, different
// source sets can produce identical inputs — the last bytes of one and the
// first of the next are indistinguishable from a single longer contribution —
// and two deployments would silently derive the same value. Length-prefixing
// makes the encoding injective, so the input determines the contributions.
//
// A source that is unhealthy fails the whole read. That is deliberate: a
// deployment that has been told a source is broken should stop and be fixed,
// not continue on the remainder while believing it has more sources than it
// does.
func Combine(sources ...Source) Source {
	return &combined{sources: sources}
}

type combined struct {
	sources []Source
}

func (c *combined) Name() string { return "combined" }

func (c *combined) Health() error {
	if len(c.sources) == 0 {
		return fmt.Errorf("%w: no sources", ErrUnhealthy)
	}
	for i, s := range c.sources {
		if err := s.Health(); err != nil {
			return fmt.Errorf("%s: %w", nameOf(s, i), err)
		}
	}
	return nil
}

func (c *combined) Read(p []byte) (int, error) {
	if err := c.Health(); err != nil {
		return 0, err
	}
	parts := make([][]byte, len(c.sources))
	for i, s := range c.sources {
		buf := make([]byte, drawPerSource)
		if _, err := io.ReadFull(s, buf); err != nil {
			return 0, fmt.Errorf("entropy: read %s: %w", nameOf(s, i), err)
		}
		parts[i] = buf
	}
	return io.ReadFull(mix(parts), p)
}

// mix is the combining construction itself, separated from reading so that the
// property it exists for can be checked directly: distinct contribution lists
// must give distinct output.
//
// Each contribution is preceded by its length. Combine happens to draw a fixed
// number of bytes from every source, which makes the lengths uniform today —
// but a construction that is only injective while every input happens to be
// the same size is one bad day from not being injective at all. The prefix is
// what makes the encoding injective for any contributions, so this stays true
// if a source ever contributes a different amount.
func mix(parts [][]byte) io.Reader {
	h := sha3.NewShake256()
	h.Write([]byte(combineTag))
	var length [8]byte
	for _, part := range parts {
		binary.LittleEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	return h
}
