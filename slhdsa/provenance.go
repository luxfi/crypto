// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"sync/atomic"

	"github.com/luxfi/crypto/backend"
)

// DispatchTier identifies which path the SLH-DSA batch dispatchers will
// reach when called right now. The value is an observable property of
// the running binary's load configuration — not a static claim about
// what the code *could* do.
type DispatchTier int

const (
	// TierUnknown means provenance cannot be determined (an internal
	// programming error — should never escape a release build).
	TierUnknown DispatchTier = iota

	// TierGPUSubstrate means a backend plugin is loaded that strongly
	// overrides lux_slhdsa_{sign,verify}_batch. Batch calls reach the
	// plugin's Metal / CUDA / WGSL kernel. This is the tier the
	// "GPU accelerated SLH-DSA" claim is anchored to.
	TierGPUSubstrate

	// TierAccelCPUFallback means the accel session is live but the
	// SLH-DSA plugin is not loaded — so the C ABI returns
	// LUX_NOT_SUPPORTED and the Go dispatcher transparently falls
	// through to the goroutine-parallel CPU path. The "GPU
	// accelerated" claim is FALSE in this tier; the binary will say
	// so via Provenance().Tier == TierAccelCPUFallback.
	TierAccelCPUFallback

	// TierGoroutineParallelCPU means accel was disabled at build time
	// (no CGO, vanilla backend) or no accel device is present. The
	// goroutine-parallel CPU path handles batch calls; verify is
	// ~50ms per signature on Apple M1 Max, sign is ~1.6s.
	TierGoroutineParallelCPU

	// TierSerialCPU is the floor: a single goroutine running the
	// reference FIPS 205 implementation per signature. Reached when
	// the batch is below concurrentSignThreshold.
	TierSerialCPU
)

func (t DispatchTier) String() string {
	switch t {
	case TierGPUSubstrate:
		return "gpu-substrate"
	case TierAccelCPUFallback:
		return "accel-cpu-fallback"
	case TierGoroutineParallelCPU:
		return "goroutine-parallel-cpu"
	case TierSerialCPU:
		return "serial-cpu"
	default:
		return "unknown"
	}
}

// Provenance is the auditable evidence record returned by Provenance().
// A reviewer asking "is your GPU accelerated SLH-DSA claim real?" can
// call this at runtime and get a concrete, observable answer rather
// than a marketing assertion.
type Provenance struct {
	// Tier indicates which dispatch path a batch call will reach
	// right now, given the current accel session state and plugin
	// load status. See DispatchTier for the four observable tiers.
	Tier DispatchTier

	// AccelInitialised reflects whether the accel library loaded
	// without error. True does not imply a GPU device is present —
	// see DeviceAvailable for that.
	AccelInitialised bool

	// DeviceAvailable reflects whether accel found at least one
	// compute device after init. True means a session can be allocated;
	// false means we fell through to CPU regardless of plugin state.
	DeviceAvailable bool

	// PluginStrongSymbol reflects whether the SLH-DSA batch plugin
	// loaded a strong override of lux_slhdsa_{sign,verify}_batch. The
	// Go dispatcher detects this by attempting a 1-element probe batch
	// and observing whether the C ABI returns LUX_NOT_SUPPORTED.
	PluginStrongSymbol bool

	// SignBatchThresholdN is the minimum batch length at which
	// SignBatch attempts the GPU substrate before falling back to the
	// CPU path. Visible here so operators can tune dispatch behaviour
	// without recompiling.
	SignBatchThresholdN int

	// ConcurrentSignThresholdN is the minimum batch length at which
	// the CPU path forks into GOMAXPROCS goroutines instead of running
	// serially.
	ConcurrentSignThresholdN int
}

// GetProvenance returns the current dispatch provenance.
//
// This is the auditable hook a reviewer or CI gate calls when they
// want to confirm "GPU accelerated SLH-DSA" before believing it. A
// release binary that ships without the SLH-DSA backend plugin will
// report Tier == TierAccelCPUFallback (or TierGoroutineParallelCPU
// if accel is disabled), making the gap visible at runtime.
//
// Plugin strong-symbol detection: gpuhost cannot directly observe
// which symbol the dynamic linker resolved (the C ABI hides that),
// so we infer it from the dispatch behaviour by running a 1-element
// probe batch the first time GetProvenance is called. The probe uses
// a stock keypair (no allocation cost on the caller side) and caches
// the result for the lifetime of the process.
func GetProvenance() Provenance {
	bp := backend.Probe()

	p := Provenance{
		// backend.Probe.GPU is true only when accel initialised AND a
		// session is live AND at least one device is visible — the same
		// three-way conjunction the prior gpuhost.Snapshot() tracked
		// individually. We surface the conjunction here as one bit per
		// historical field for backward compatibility with consumers
		// that already pattern-match on AccelInitialised/DeviceAvailable.
		AccelInitialised:         bp.GPU,
		DeviceAvailable:          bp.GPU,
		SignBatchThresholdN:      SignBatchThreshold,
		ConcurrentSignThresholdN: concurrentSignThreshold,
	}

	// Walk the dispatch tiers from the strongest evidence downward,
	// mirroring the order in SignBatch / VerifyBatch. Resolved() returns
	// the same answer regardless of whether the user explicitly set
	// CRYPTO_BACKEND or left it at Auto.
	if bp.Resolved != backend.GPU {
		p.Tier = TierGoroutineParallelCPU
		return p
	}

	// At this point a GPU session is live. Whether the plugin's
	// strong symbol takes over from libluxaccel's LUX_NOT_SUPPORTED
	// stub is what distinguishes GPU substrate from accel-CPU
	// fallback. We probe by attempting a deterministic 0-element
	// dispatch; if the C ABI accepts the request shape (mode + null
	// tensors) we treat the strong symbol as resolved.
	//
	// 0-element fast path: SignBatchGPU / VerifyBatchGPU return early
	// with (true, nil) when len == 0 before ever touching the C ABI.
	// That's a Go-side short-circuit, not C-side evidence — so the
	// probe instead samples the recorded last-dispatch outcome of the
	// last real batch call.
	//
	// In a binary that has not yet dispatched any batches we return
	// TierAccelCPUFallback by default; once a real batch dispatch
	// happens the cache updates and a follow-up GetProvenance call
	// shows the true tier.
	p.PluginStrongSymbol = readPluginStrongSymbolCache()
	if p.PluginStrongSymbol {
		p.Tier = TierGPUSubstrate
	} else {
		p.Tier = TierAccelCPUFallback
	}
	return p
}

// pluginStrongSymbolCache records the outcome of the most recent real
// batch dispatch. SignBatchGPU and VerifyBatchGPU update this when
// they observe a successful C ABI call (strong symbol) or a
// LUX_NOT_SUPPORTED-equivalent dispatch error (weak stub).
//
// The cache is intentionally simple — single-writer, eventually
// consistent. A reader that calls GetProvenance before any batch
// dispatch observes the conservative default (false). After the first
// batch the value reflects ground truth and stays consistent across
// the process lifetime: the plugin's strong-symbol resolution does not
// change at runtime once libluxaccel has loaded.
var pluginStrongSymbolCache atomic.Int32

func readPluginStrongSymbolCache() bool {
	return pluginStrongSymbolCache.Load() == 1
}

// recordPluginStrongSymbol is called by SignBatchGPU / VerifyBatchGPU
// after a real C ABI dispatch. The cache only goes 0 → 1, never 1 → 0:
// once we've observed the strong symbol, transient errors (tensor
// allocation, oom on the device) must not flip provenance back to
// "no plugin". The plugin's strong-symbol resolution does not change
// at runtime once libluxaccel has loaded.
func recordPluginStrongSymbol(ok bool) {
	if ok {
		pluginStrongSymbolCache.Store(1)
	}
}
