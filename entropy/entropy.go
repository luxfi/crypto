// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package entropy supplies the secret material every other primitive here
// draws from: ML-DSA and ML-KEM key generation, TLS keys, signing nonces,
// threshold dealer seeds. Each is exactly as unpredictable as the draw that
// produced it, and no more.
//
// A source is bytes plus a verdict on whether those bytes are worth anything.
// The verdict is the part that is easy to leave out: a physical noise source
// that has drifted, saturated or stuck still emits bytes of the expected
// length, and nothing downstream can tell. A key generated from it verifies,
// signs and behaves correctly in every respect except the one that matters.
// So a source here reports its own health, and refuses to emit rather than
// emit weakly.
//
// Sources compose (see Combine), and the composition is chosen so that adding
// one can never make the result worse. That is what allows an unproven device
// to be introduced to a running deployment: at worst it contributes nothing.
//
// What this package is not for: consensus. Values drawn here are known to one
// party by construction, which is what a secret needs and what agreement
// forbids — a value only the proposer can produce is one it can produce
// repeatedly. Public randomness comes from a threshold protocol whose output
// is verifiable because it is a signature. See LP-187.
package entropy

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnhealthy is returned by Read when a source's health tests are failing.
// It is deliberately not recoverable by retrying: a caller that receives it
// must fail the operation rather than generate a key from a source that has
// stopped being random.
var ErrUnhealthy = errors.New("entropy: source is not healthy")

// Source is bytes and a verdict on them.
//
// Read fails closed. It returns an error rather than short or low-quality
// output, because a caller cannot distinguish weak bytes from strong ones by
// looking at them.
type Source interface {
	io.Reader

	// Health reports nil while startup and continuous tests are passing.
	Health() error
}

// Named is a Source that can say what it is, for operators reading logs and
// for evidence that names which sources a deployment held.
type Named interface {
	Source
	Name() string
}

// nameOf is the name a source reports, or a placeholder for one that does not.
func nameOf(s Source, i int) string {
	if n, ok := s.(Named); ok {
		return n.Name()
	}
	return fmt.Sprintf("source-%d", i)
}
