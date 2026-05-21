// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"errors"
	"sync"
)

// ErrInvalidMode is returned when an unknown ML-DSA mode is passed to a
// batch entry point. Modes must be one of {2, 3, 5} per FIPS 204.
var ErrInvalidMode = errors.New("mldsa/gpu: invalid ML-DSA mode (want 2, 3, or 5)")

// ErrShapeMismatch is returned when the lengths of batched input slices
// disagree (e.g. len(msgs) != len(sigs) in VerifyBatch).
var ErrShapeMismatch = errors.New("mldsa/gpu: batch shape mismatch")

// ErrInvalidLength is returned when a polynomial slice is not exactly N
// coefficients long.
var ErrInvalidLength = errors.New("mldsa/gpu: polynomial must be exactly 256 coefficients")

// Default GPU dispatch threshold. Below this batch size, the dispatcher
// stays on the CPU because the per-call GPU launch overhead exceeds the
// throughput win. Tuned for Apple M-series; CUDA hosts will tend to
// benefit from a lower threshold but the value is conservative so it
// never regresses CPU-only callers.
const (
	// DefaultNTTBatchThreshold is the minimum number of polynomials a
	// batch call must contain before dispatch flips to GPU. One NTT
	// operates on a length-256 uint32 slice (1 KiB); the threshold is
	// chosen so a single tensor allocation + sync amortises across at
	// least 16 polynomials.
	DefaultNTTBatchThreshold = 16

	// DefaultSignBatchThreshold is the minimum number of messages a
	// batch sign call must contain to flip to GPU. ML-DSA signing is
	// memory-bandwidth bound (large secret keys); 8 is a safe floor.
	DefaultSignBatchThreshold = 8

	// DefaultVerifyBatchThreshold is the minimum number of (msg, sig, pk)
	// triples a batch verify call must contain to flip to GPU. Verify is
	// cheaper per call, so the breakeven is higher.
	DefaultVerifyBatchThreshold = 16
)

// Accelerator is the public handle to the ML-DSA GPU/CPU dispatcher.
// One instance is enough for the whole process; use GetAccelerator() to
// fetch the lazily-initialised singleton.
//
// All methods are safe for concurrent use.
type Accelerator struct {
	mu       sync.RWMutex
	engine   engine
	thrNTT   int
	thrSign  int
	thrVrfy  int
	gpuCalls uint64
	cpuCalls uint64
}

// engine is the build-tag-selected backend that drives the GPU dispatch.
// Two implementations exist:
//
//   - cgoEngine (build tag "cgo")     — luxfi/accel-backed GPU dispatch.
//   - cpuEngine (build tag "!cgo")    — pure-Go CPU dispatch.
//
// Both implementations satisfy the same interface so the public API in
// this file does not branch on build tag.
type engine interface {
	// available reports whether the engine can dispatch to the GPU.
	// CPU-only engines return false.
	available() bool

	// backend returns the active backend name, e.g. "metal", "cuda",
	// "cpu", or "" when no engine is initialised.
	backend() string

	// nttForwardBatch runs forward NTT on every polynomial in polys.
	// The engine is permitted to dispatch some to GPU and some to CPU.
	nttForwardBatch(polys []*[N]uint32) error

	// nttInverseBatch is the inverse of nttForwardBatch.
	nttInverseBatch(polys []*[N]uint32) error

	// polyMulBatch computes c[i] = a[i] * b[i] in R_q for every i.
	polyMulBatch(a, b []*[N]uint32, c []*[N]uint32) error

	// signBatch signs each message in msgs with the matching private
	// key in sks and writes the result to sigs[i]. mode is the FIPS 204
	// security level (2, 3, 5). All slices must have the same length.
	signBatch(mode Mode, msgs [][]byte, sks [][]byte, sigs [][]byte) error

	// verifyBatch verifies each signature in sigs against the matching
	// (msg, pk) pair. Returns one boolean per input.
	verifyBatch(mode Mode, msgs [][]byte, sigs [][]byte, pks [][]byte) ([]bool, error)
}

// newAccelerator constructs an Accelerator backed by the build-tag-
// selected engine (cgo → GPU, !cgo → CPU). Default thresholds are used.
func newAccelerator() *Accelerator {
	return &Accelerator{
		engine:  newEngine(),
		thrNTT:  DefaultNTTBatchThreshold,
		thrSign: DefaultSignBatchThreshold,
		thrVrfy: DefaultVerifyBatchThreshold,
	}
}

// Available reports whether the underlying engine has a working GPU
// session. CPU-only builds always return false.
func (a *Accelerator) Available() bool {
	if a == nil || a.engine == nil {
		return false
	}
	return a.engine.available()
}

// Backend returns the active backend name ("metal", "cuda", "cpu",
// "webgpu") or "cpu" when no GPU is available.
func (a *Accelerator) Backend() string {
	if a == nil || a.engine == nil {
		return "cpu"
	}
	if b := a.engine.backend(); b != "" {
		return b
	}
	return "cpu"
}

// SetThresholds overrides the default GPU-dispatch thresholds. Passing
// zero for a value retains its current setting. Useful for tuning on a
// specific platform or for forcing CPU paths in tests.
func (a *Accelerator) SetThresholds(ntt, sign, verify int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ntt > 0 {
		a.thrNTT = ntt
	}
	if sign > 0 {
		a.thrSign = sign
	}
	if verify > 0 {
		a.thrVrfy = verify
	}
}

// Stats returns the cumulative number of GPU and CPU dispatches since
// the accelerator was created. Useful for verifying that the threshold
// routing is doing what we think it is in benchmarks.
func (a *Accelerator) Stats() (gpu, cpu uint64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.gpuCalls, a.cpuCalls
}

// NTTForward performs the FIPS 204 forward NTT in-place on p.
//
// Always runs on the CPU (single-poly latency is dominated by host
// dispatch overhead). Callers that have many polynomials should use
// NTTForwardBatch instead.
func (a *Accelerator) NTTForward(p *[N]uint32) {
	NTTForwardCPU(p)
	a.mu.Lock()
	a.cpuCalls++
	a.mu.Unlock()
}

// NTTInverse performs the FIPS 204 inverse NTT in-place on p.
func (a *Accelerator) NTTInverse(p *[N]uint32) {
	NTTInverseCPU(p)
	a.mu.Lock()
	a.cpuCalls++
	a.mu.Unlock()
}

// NTTForwardBatch performs forward NTT on every polynomial in polys.
// Below DefaultNTTBatchThreshold the call stays on the CPU; above it the
// call is dispatched to the engine, which may go to the GPU.
func (a *Accelerator) NTTForwardBatch(polys []*[N]uint32) error {
	if len(polys) == 0 {
		return nil
	}
	a.mu.RLock()
	thr := a.thrNTT
	useGPU := a.engine.available() && len(polys) >= thr
	a.mu.RUnlock()

	if useGPU {
		if err := a.engine.nttForwardBatch(polys); err == nil {
			a.bump(true, uint64(len(polys)))
			return nil
		}
		// Fall through to CPU on engine failure.
	}
	for _, p := range polys {
		NTTForwardCPU(p)
	}
	a.bump(false, uint64(len(polys)))
	return nil
}

// NTTInverseBatch is the inverse of NTTForwardBatch.
func (a *Accelerator) NTTInverseBatch(polys []*[N]uint32) error {
	if len(polys) == 0 {
		return nil
	}
	a.mu.RLock()
	thr := a.thrNTT
	useGPU := a.engine.available() && len(polys) >= thr
	a.mu.RUnlock()

	if useGPU {
		if err := a.engine.nttInverseBatch(polys); err == nil {
			a.bump(true, uint64(len(polys)))
			return nil
		}
	}
	for _, p := range polys {
		NTTInverseCPU(p)
	}
	a.bump(false, uint64(len(polys)))
	return nil
}

// PolyMulBatch computes c[i] = a[i] * b[i] in R_q for each i. All three
// slices must have the same length. Above the NTT threshold this is
// dispatched to the engine (which composes NTT∘mul∘INTT in one kernel);
// below it the CPU path is used.
func (a *Accelerator) PolyMulBatch(aIn, bIn, cOut []*[N]uint32) error {
	if len(aIn) != len(bIn) || len(aIn) != len(cOut) {
		return ErrShapeMismatch
	}
	if len(aIn) == 0 {
		return nil
	}
	a.mu.RLock()
	thr := a.thrNTT
	useGPU := a.engine.available() && len(aIn) >= thr
	a.mu.RUnlock()

	if useGPU {
		if err := a.engine.polyMulBatch(aIn, bIn, cOut); err == nil {
			a.bump(true, uint64(len(aIn)))
			return nil
		}
	}
	for i := range aIn {
		out := PolyMulCPU(aIn[i], bIn[i])
		*cOut[i] = out
	}
	a.bump(false, uint64(len(aIn)))
	return nil
}

// SignBatch signs a batch of messages. mode must be one of {2, 3, 5}.
// len(msgs), len(sks), and len(sigs) must agree; the engine writes the
// signature for msgs[i] into sigs[i].
//
// Below DefaultSignBatchThreshold this falls through to per-element CPU
// signing via the engine; above it the engine batches into a single
// luxfi/accel.MLDSASignBatch call (CGO build) or N parallel CPU calls
// (no-CGO build).
func (a *Accelerator) SignBatch(mode Mode, msgs, sks, sigs [][]byte) error {
	if _, ok := ParamsFor(mode); !ok {
		return ErrInvalidMode
	}
	if len(msgs) != len(sks) || len(msgs) != len(sigs) {
		return ErrShapeMismatch
	}
	if len(msgs) == 0 {
		return nil
	}
	a.mu.RLock()
	thr := a.thrSign
	useGPU := a.engine.available() && len(msgs) >= thr
	a.mu.RUnlock()

	if useGPU {
		if err := a.engine.signBatch(mode, msgs, sks, sigs); err == nil {
			a.bump(true, uint64(len(msgs)))
			return nil
		}
	}
	// CPU fallback uses the engine's own per-element CPU path so the
	// non-CGO build can share the same code.
	if err := a.engine.signBatch(mode, msgs, sks, sigs); err != nil {
		return err
	}
	a.bump(false, uint64(len(msgs)))
	return nil
}

// VerifyBatch verifies a batch of signatures. mode must be one of
// {2, 3, 5}. All slices must agree in length; the returned slice has
// one bool per (msg, sig, pk) triple.
//
// Verify is deterministic per FIPS 204 §5.3 so CPU and GPU paths produce
// byte-identical accept/reject decisions. Below DefaultVerifyBatchThreshold
// the call stays on the CPU.
func (a *Accelerator) VerifyBatch(mode Mode, msgs, sigs, pks [][]byte) ([]bool, error) {
	if _, ok := ParamsFor(mode); !ok {
		return nil, ErrInvalidMode
	}
	if len(msgs) != len(sigs) || len(msgs) != len(pks) {
		return nil, ErrShapeMismatch
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	a.mu.RLock()
	thr := a.thrVrfy
	useGPU := a.engine.available() && len(msgs) >= thr
	a.mu.RUnlock()

	if useGPU {
		if res, err := a.engine.verifyBatch(mode, msgs, sigs, pks); err == nil {
			a.bump(true, uint64(len(msgs)))
			return res, nil
		}
	}
	res, err := a.engine.verifyBatch(mode, msgs, sigs, pks)
	if err != nil {
		return nil, err
	}
	a.bump(false, uint64(len(msgs)))
	return res, nil
}

// bump records a dispatch decision in the counters.
func (a *Accelerator) bump(gpu bool, n uint64) {
	a.mu.Lock()
	if gpu {
		a.gpuCalls += n
	} else {
		a.cpuCalls += n
	}
	a.mu.Unlock()
}

// Available reports whether GPU acceleration is available on the
// process-global accelerator instance.
func Available() bool { return GetAccelerator().Available() }

// Backend returns the active backend name on the process-global
// accelerator.
func Backend() string { return GetAccelerator().Backend() }

// Process-global accelerator: lazily initialised, safe for concurrent
// use. Callers that need to tune thresholds or query stats should use
// GetAccelerator() and operate on the returned handle.
var (
	globalAccel     *Accelerator
	globalAccelOnce sync.Once
)

// GetAccelerator returns the process-global ML-DSA accelerator. The
// first call initialises the engine; subsequent calls are O(1).
func GetAccelerator() *Accelerator {
	globalAccelOnce.Do(func() { globalAccel = newAccelerator() })
	return globalAccel
}
