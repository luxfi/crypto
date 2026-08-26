// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package entropy

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"sync"
)

// OS is the platform generator. It is always available, needs no health
// testing of its own — the kernel does that — and is the reason hardware can
// be added to a deployment without risk: it is present in every combination,
// so the combined result is never worse than the platform alone.
//
// A deployment whose only source is a device it cannot itself audit has not
// removed trust from the picture. It has moved it into a vendor.
func OS() Source { return osSource{} }

type osSource struct{}

func (osSource) Name() string               { return "os" }
func (osSource) Health() error              { return nil }
func (osSource) Read(p []byte) (int, error) { return io.ReadFull(rand.Reader, p) }

// Device is a hardware entropy source read from a character device, held to
// the health tests of SP 800-90B.
//
// minEntropy is the bits of min-entropy per byte the device claims. It is
// supplied by the caller rather than read from the device because it is not a
// property the device can assert: it is the conclusion of an assessment of
// that hardware, and the tests here check that the device still behaves like
// the one that was assessed. A device shipped without such an assessment
// should be given a conservative figure, and described as unassessed.
//
// Raw device bytes are never returned. They are conditioned first, because a
// physical source is biased and correlated even when it is working.
func Device(path string, minEntropy float64) (Source, error) {
	if minEntropy <= 0 || minEntropy > 8 {
		return nil, fmt.Errorf("entropy: min-entropy per byte must be in (0, 8], got %v", minEntropy)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("entropy: open %s: %w", path, err)
	}
	d := &device{
		path:    path,
		f:       f,
		mon:     newMonitor(minEntropy, false),
		entropy: minEntropy,
	}
	// Startup: the tests must pass over a run of samples before anything is
	// released, so a device that comes up broken is refused rather than used
	// once and then noticed.
	warm := make([]byte, startupSamples)
	if _, err := io.ReadFull(f, warm); err != nil {
		f.Close()
		return nil, fmt.Errorf("entropy: startup read %s: %w", path, err)
	}
	if err := d.mon.observe(warm); err != nil {
		f.Close()
		return nil, fmt.Errorf("entropy: %s failed startup: %w", path, err)
	}
	return d, nil
}

type device struct {
	path    string
	entropy float64

	mu  sync.Mutex
	f   *os.File
	mon *monitor
}

func (d *device) Name() string { return d.path }

func (d *device) Health() error { return d.mon.health() }

// Read draws raw samples, tests them, and returns the conditioned result.
//
// The amount drawn is set by the claimed min-entropy: to release n bytes the
// source must observe enough raw bytes to hold at least 2n bytes' worth of
// entropy, which is the margin SP 800-90B asks of a conditioner. A device
// claiming less per byte is simply read from more.
func (d *device) Read(p []byte) (int, error) {
	if err := d.mon.health(); err != nil {
		return 0, err
	}
	need := rawFor(len(p), d.entropy)

	d.mu.Lock()
	raw := make([]byte, need)
	_, err := io.ReadFull(d.f, raw)
	d.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("entropy: read %s: %w", d.path, err)
	}

	if err := d.mon.observe(raw); err != nil {
		return 0, err
	}
	return io.ReadFull(condition(raw), p)
}

func (d *device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f.Close()
}

// rawFor is how many raw bytes carry 2n bytes' worth of entropy at h bits per
// byte. The doubling is the conditioner's input margin: a conditioner credited
// with producing n bytes of full-entropy output is fed at least twice that.
func rawFor(n int, h float64) int {
	need := int(float64(2*n*8)/h) + 1
	if need < startupSamples/8 {
		need = startupSamples / 8
	}
	return need
}
