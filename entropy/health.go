// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package entropy

import (
	"fmt"
	"math"
	"sync"
)

// The two continuous tests of SP 800-90B §4.4, which are what separates an
// entropy source from a noise source. Both answer the same question — has this
// source stopped producing what it claims — and they answer it in different
// directions: one catches a source that has stuck, the other a source whose
// distribution has collapsed without stopping.
//
// Each is sized so a healthy source trips it with probability at most
// falsePositive. That bound is the whole design constraint: too loose and a
// degraded source keeps running, too tight and a working one is declared
// broken. It is stated here rather than tuned per deployment so that two
// deployments mean the same thing by "healthy".

// falsePositive is the probability a healthy source trips a test. SP 800-90B
// recommends a value in this range; at 2^-40 a source sampled continuously
// runs for a very long time between spurious faults.
const falsePositive = 1.0 / (1 << 40)

// adaptiveWindow is the sample count an adaptive-proportion test examines.
// SP 800-90B §4.4.2 sets 1024 for binary sources and 512 otherwise.
const (
	adaptiveWindowBinary = 1024
	adaptiveWindowOther  = 512
)

// A Test observes samples and reports whether the source still looks like the
// one that was assessed.
type Test interface {
	// Observe takes one sample. It returns an error the first time the source
	// fails, and keeps returning one thereafter: a source that has failed
	// stays failed until something re-establishes it.
	Observe(sample byte) error
	Reset()
}

// repetitionCount fails when one value repeats more times consecutively than a
// source of the claimed entropy plausibly would. It catches the loudest
// failure — a source that has stuck at a value — within a few samples.
type repetitionCount struct {
	cutoff int
	last   byte
	run    int
	failed error
}

// newRepetitionCount builds the test for a source claiming h bits of
// min-entropy per sample. The cutoff is
//
//	C = 1 + ceil(-log2(alpha) / h)
//
// which is SP 800-90B §4.4.1: the run length whose probability under the
// claimed entropy first drops below alpha.
func newRepetitionCount(h float64) *repetitionCount {
	return &repetitionCount{cutoff: 1 + int(math.Ceil(-math.Log2(falsePositive)/h))}
}

func (t *repetitionCount) Observe(s byte) error {
	if t.failed != nil {
		return t.failed
	}
	if t.run > 0 && s == t.last {
		t.run++
	} else {
		t.last, t.run = s, 1
	}
	if t.run >= t.cutoff {
		t.failed = fmt.Errorf("%w: repetition count: value repeated %d times, cutoff %d",
			ErrUnhealthy, t.run, t.cutoff)
		return t.failed
	}
	return nil
}

func (t *repetitionCount) Reset() { t.last, t.run, t.failed = 0, 0, nil }

// adaptiveProportion fails when one value takes too large a share of a window.
// It catches the quieter failure: a source still changing value, but drawn
// from far fewer values than it claims.
type adaptiveProportion struct {
	window int
	cutoff int
	ref    byte
	seen   int
	count  int
	failed error
}

// newAdaptiveProportion builds the test for a source claiming h bits of
// min-entropy per sample over the given window.
func newAdaptiveProportion(h float64, window int) *adaptiveProportion {
	return &adaptiveProportion{window: window, cutoff: binomialCutoff(window, math.Exp2(-h))}
}

func (t *adaptiveProportion) Observe(s byte) error {
	if t.failed != nil {
		return t.failed
	}
	if t.seen == 0 {
		// The first sample of a window is the value the rest are counted
		// against, so the window measures how often the source returns to
		// wherever it happened to be.
		t.ref, t.count, t.seen = s, 1, 1
		return nil
	}
	t.seen++
	if s == t.ref {
		t.count++
		if t.count >= t.cutoff {
			t.failed = fmt.Errorf("%w: adaptive proportion: value seen %d times in %d samples, cutoff %d",
				ErrUnhealthy, t.count, t.seen, t.cutoff)
			return t.failed
		}
	}
	if t.seen >= t.window {
		t.seen = 0
	}
	return nil
}

func (t *adaptiveProportion) Reset() { t.ref, t.seen, t.count, t.failed = 0, 0, 0, nil }

// binomialCutoff returns the smallest c for which observing c or more
// occurrences in n trials, each with probability p, is at most falsePositive.
//
// It sums the upper tail directly from the top down. The terms fall away
// quickly, so this reaches the answer in far fewer steps than n, and summing
// from the small end keeps the running total from being dominated before the
// interesting terms arrive.
func binomialCutoff(n int, p float64) int {
	if p <= 0 {
		return 2 // any repeat at all is impossible; one is enough to fail
	}
	if p >= 1 {
		return n + 1 // every sample is the same value; never fails
	}
	tail := 0.0
	for c := n; c >= 1; c-- {
		tail += binomialPMF(n, c, p)
		if tail > falsePositive {
			// c is the first count whose tail is too likely to be a fault, so
			// the cutoff is one above it.
			return c + 1
		}
	}
	return 1
}

// binomialPMF is C(n,k) p^k (1-p)^(n-k), computed in logs because C(n,k)
// overflows long before the probability becomes interesting.
func binomialPMF(n, k int, p float64) float64 {
	if k < 0 || k > n {
		return 0
	}
	logC, _ := math.Lgamma(float64(n) + 1)
	lk, _ := math.Lgamma(float64(k) + 1)
	lnk, _ := math.Lgamma(float64(n-k) + 1)
	logP := logC - lk - lnk + float64(k)*math.Log(p) + float64(n-k)*math.Log1p(-p)
	return math.Exp(logP)
}

// monitor runs the required tests over a stream of samples and remembers the
// first failure. It is the piece a source embeds to become an entropy source.
type monitor struct {
	mu     sync.Mutex
	tests  []Test
	warmed bool
	need   int
	got    int
	failed error
}

// startupSamples is how many samples must pass before any output is released.
// SP 800-90B requires at least 1024 consecutive samples at startup.
const startupSamples = 1024

// newMonitor builds the required test set for a source claiming h bits of
// min-entropy per sample. binary selects the window size.
func newMonitor(h float64, binary bool) *monitor {
	w := adaptiveWindowOther
	if binary {
		w = adaptiveWindowBinary
	}
	return &monitor{
		tests: []Test{newRepetitionCount(h), newAdaptiveProportion(h, w)},
		need:  startupSamples,
	}
}

// observe runs every test over the samples. Once it has returned an error it
// keeps returning one: a source that failed its tests is not trusted again by
// being asked twice.
func (m *monitor) observe(samples []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return m.failed
	}
	for _, s := range samples {
		for _, t := range m.tests {
			if err := t.Observe(s); err != nil {
				m.failed = err
				return err
			}
		}
		if m.got < m.need {
			m.got++
		}
	}
	if m.got >= m.need {
		m.warmed = true
	}
	return nil
}

// health reports why output may not be released, or nil.
func (m *monitor) health() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return m.failed
	}
	if !m.warmed {
		return fmt.Errorf("%w: startup incomplete, %d of %d samples", ErrUnhealthy, m.got, m.need)
	}
	return nil
}
