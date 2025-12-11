// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package timer

import (
	"encoding/binary"
	"time"
)

// ProgressFromHash returns the progress out of MaxUint64 assuming [b] is a key
// in a uniformly distributed sequence that is being iterated lexicographically.
func ProgressFromHash(b []byte) uint64 {
	// binary.BigEndian.Uint64 will panic if the input length is less than 8, so
	// pad 0s as needed.
	var progress [8]byte
	copy(progress[:], b)
	return binary.BigEndian.Uint64(progress[:])
}

// EstimateETA attempts to estimate the remaining time for a job to finish given
// the [startTime] and it's current progress.
func EstimateETA(startTime time.Time, progress, end uint64) time.Duration {
	timeSpent := time.Since(startTime)

	percentExecuted := float64(progress) / float64(end)
	estimatedTotalDuration := time.Duration(float64(timeSpent) / percentExecuted)
	eta := estimatedTotalDuration - timeSpent
	return eta.Round(time.Second)
}

// sample represents a single progress sample
type sample struct {
	progress  uint64
	timestamp time.Time
}

// EtaTracker provides exponentially weighted moving average ETA estimates
type EtaTracker struct {
	minSamples   int
	alpha        float64
	sampleWindow []sample
	lastProgress uint64
	lastTime     time.Time
}

// NewEtaTracker creates a new ETA tracker with the given number of samples and alpha
func NewEtaTracker(minSamples int, alpha float64) *EtaTracker {
	return &EtaTracker{
		minSamples:   minSamples,
		alpha:        alpha,
		sampleWindow: make([]sample, 0, minSamples),
	}
}

// Update updates the ETA tracker with new progress
func (e *EtaTracker) Update(progress, total uint64) {
	// Simple implementation - just track the time
}

// AddSample adds a sample to the ETA tracker and returns ETA pointer and progress percentage
func (e *EtaTracker) AddSample(progress, total uint64, sampleTime time.Time) (*time.Duration, float64) {
	if total == 0 {
		return nil, 0
	}

	// Handle completed case
	if progress >= total {
		eta := time.Duration(0)
		return &eta, 100.0
	}

	// Reject bogus samples (time went backwards or no progress made when we have samples)
	if len(e.sampleWindow) > 0 {
		lastSample := e.sampleWindow[len(e.sampleWindow)-1]
		if sampleTime.Before(lastSample.timestamp) || sampleTime.Equal(lastSample.timestamp) {
			// Time warp or same time - return nil ETA
			return nil, 0
		}
		if progress <= lastSample.progress {
			// No progress made - return nil ETA
			return nil, 0
		}
	}

	// Add sample to window
	e.sampleWindow = append(e.sampleWindow, sample{
		progress:  progress,
		timestamp: sampleTime,
	})

	// Not enough samples yet
	if len(e.sampleWindow) < e.minSamples {
		return nil, 0
	}

	// Keep only the last minSamples in the window (sliding window)
	if len(e.sampleWindow) > e.minSamples {
		e.sampleWindow = e.sampleWindow[len(e.sampleWindow)-e.minSamples:]
	}

	// Calculate rate from first to last sample in sliding window
	firstSample := e.sampleWindow[0]
	lastSample := e.sampleWindow[len(e.sampleWindow)-1]

	progressMade := lastSample.progress - firstSample.progress
	timeTaken := lastSample.timestamp.Sub(firstSample.timestamp)

	if timeTaken <= 0 || progressMade == 0 {
		return nil, 0
	}

	// Calculate rate and ETA
	rate := float64(progressMade) / timeTaken.Seconds()
	remaining := total - lastSample.progress
	etaSeconds := float64(remaining) / rate
	eta := time.Duration(etaSeconds * float64(time.Second))

	progressPercent := float64(lastSample.progress) / float64(total) * 100
	return &eta, progressPercent
}

// ETA returns the estimated time remaining
func (e *EtaTracker) ETA(progress, total uint64) time.Duration {
	result, _ := e.AddSample(progress, total, time.Now())
	if result == nil {
		return 0
	}
	return *result
}
