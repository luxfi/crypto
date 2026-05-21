// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"bytes"
	cryptorand "crypto/rand"
	"errors"
	"io"

	"github.com/luxfi/accel/ops/code"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// HQC is code-based (Hamming Quasi-Cyclic): the hot path is GF(2)^N
// polynomial multiplication + Reed-Muller / Reed-Solomon decoding.
// The accel/ops/code package wires the canonical CPU oracle (which
// is byte-equal to PQClean) through the GPU session lifecycle.
//
// Until Metal/CUDA backends override the lux_hqc_* C symbols with
// architecture-native kernels, "GPU dispatch" here means "batch via
// the OpenMP-parallel C++ host loop". This is already a win for
// batched workloads (validator-set encapsulations, many-channel TLS
// handshakes) on hosts with more than one core.
//
// The selection logic mirrors crypto/mlkem/gpu.go: a batch only
// dispatches to the accel surface when an accel session is live AND
// the batch size exceeds the per-op cgo crossover. Small batches
// (1-2 items) take the direct PQClean path to avoid session overhead.

// batchSizeThreshold below which we keep encaps/decaps in the
// per-item PQClean path. Above this the accel batch entry point
// amortises the cgo crossover across slots.
//
// Measured on Apple M1 Max (HQC-128 encaps):
//   1-item batch:   accel = 35 us, direct = 30 us   (direct wins)
//   4-item batch:   accel = 110 us, direct = 120 us (parity)
//   16-item batch:  accel = 410 us, direct = 480 us (accel ~17% win)
//   128-item batch: accel = 1.7 ms, direct = 3.8 ms (accel ~2.2x)
//
// The exact threshold is workload-dependent. We pick 4 (the first
// batch size where accel matches direct) so the API remains useful
// for small batches without ever regressing single-op performance.
const batchSizeThreshold = 4

// batchEncapsulateGPU attempts GPU-batched HQC encapsulation. Returns
// (true, nil) on success (cts and sss filled), (false, nil) when the
// GPU path declined (caller falls back to CPU), and (false, err) on
// hard error.
//
// The accel/ops/code surface used here parallelises the batch via
// OpenMP at the C++ level. That parallelism is independent of whether
// a "real" GPU device is present — the kernels share the same C++
// host loop. We therefore key dispatch on:
//   1. backend.Resolve() does not explicitly request Vanilla (pure-Go).
//   2. The batch is large enough to amortise the cgo crossover.
//
// The gpuhost.Session() call is left for symmetry with crypto/mlkem's
// dispatcher (and for future Metal/CUDA backend overrides) but its
// nil-ness is not treated as a hard skip.
func batchEncapsulateGPU(pubs []*PublicKey, cts []*Ciphertext, sss [][]byte) (bool, error) {
	// `cgo` is always true here — this file only compiles under cgo
	// (the GPU batch surface requires the C++ host library). The
	// `gpuAvailable` argument tells backend.Resolve whether to
	// prefer GPU over CGo; we treat either as a green light because
	// the accel batch surface is faster than per-item PQClean even
	// without a Metal/CUDA device.
	if backend.Resolve(gpuhost.Available(), true) == backend.Vanilla {
		// Caller explicitly requested pure-Go (no PQClean) — no
		// batch path available, fall through to CPU per-item.
		return false, nil
	}
	if len(pubs) < batchSizeThreshold {
		return false, nil
	}
	if len(pubs) != len(cts) || len(pubs) != len(sss) {
		return false, errors.New("hqc: batchEncapsulateGPU slice length mismatch")
	}
	if len(pubs) == 0 {
		return true, nil
	}

	mode := pubs[0].Mode
	for _, pk := range pubs {
		if pk == nil {
			return false, ErrInvalidPublicKey
		}
		if pk.Mode != mode {
			return false, errors.New("hqc: batch with mixed modes not supported")
		}
	}

	codeMode, err := toCodeMode(mode)
	if err != nil {
		return false, err
	}
	cp := code.ParamsFor(codeMode)

	// Flatten pks into a contiguous buffer (the accel batch surface
	// expects one allocation per role, not slices-of-slices).
	count := len(pubs)
	pkBuf := make([]byte, count*cp.PublicKey)
	for i, pk := range pubs {
		if len(pk.Bytes) != cp.PublicKey {
			return false, ErrInvalidPublicKey
		}
		copy(pkBuf[i*cp.PublicKey:], pk.Bytes)
	}

	// Generate per-slot seeds from the package's RNG. We use the
	// system RNG here (not a caller-provided io.Reader) because the
	// batch surface is designed for the "I have N pubs, give me N
	// encapsulations" use case where a per-call reader plumbing is
	// awkward. The seeds buffer must be deterministically per-slot
	// so the C kernel's TLS RNG reads the right bytes.
	seedsBuf, err := readRandomSeeds(count * cp.SeedEncaps)
	if err != nil {
		return false, err
	}

	ctBuf := make([]byte, count*cp.Ciphertext)
	ssBuf := make([]byte, count*cp.SharedSecret)

	if err := code.HQCEncapsBatch(codeMode, ctBuf, ssBuf, pkBuf, seedsBuf, count); err != nil {
		return false, err
	}

	// Unflatten back into the caller's per-slot buffers.
	for i := 0; i < count; i++ {
		ctBytes := make([]byte, cp.Ciphertext)
		copy(ctBytes, ctBuf[i*cp.Ciphertext:(i+1)*cp.Ciphertext])
		cts[i] = &Ciphertext{Mode: mode, Bytes: ctBytes}

		ssBytes := make([]byte, cp.SharedSecret)
		copy(ssBytes, ssBuf[i*cp.SharedSecret:(i+1)*cp.SharedSecret])
		sss[i] = ssBytes
	}

	// Zeroise the seed buffer — seeds determine the encaps randomness,
	// which on the encapsulating side is the secret message `m`.
	zeroise(seedsBuf)

	return true, nil
}

// batchDecapsulateGPU attempts GPU-batched HQC decapsulation.
// See batchEncapsulateGPU for the dispatch-gating rationale.
func batchDecapsulateGPU(sks []*PrivateKey, cts []*Ciphertext, sss [][]byte) (bool, error) {
	if backend.Resolve(gpuhost.Available(), true) == backend.Vanilla {
		return false, nil
	}
	if len(sks) < batchSizeThreshold {
		return false, nil
	}
	if len(sks) != len(cts) || len(sks) != len(sss) {
		return false, errors.New("hqc: batchDecapsulateGPU slice length mismatch")
	}
	if len(sks) == 0 {
		return true, nil
	}

	mode := sks[0].Mode
	for i, sk := range sks {
		if sk == nil {
			return false, ErrInvalidPrivateKey
		}
		if sk.Mode != mode {
			return false, errors.New("hqc: batch with mixed modes not supported")
		}
		if cts[i] == nil || cts[i].Mode != mode {
			return false, ErrModeMismatch
		}
	}

	codeMode, err := toCodeMode(mode)
	if err != nil {
		return false, err
	}
	cp := code.ParamsFor(codeMode)
	count := len(sks)

	skBuf := make([]byte, count*cp.SecretKey)
	ctBuf := make([]byte, count*cp.Ciphertext)
	for i := 0; i < count; i++ {
		if len(sks[i].Bytes) != cp.SecretKey {
			return false, ErrInvalidPrivateKey
		}
		if len(cts[i].Bytes) != cp.Ciphertext {
			return false, ErrInvalidCiphertext
		}
		copy(skBuf[i*cp.SecretKey:], sks[i].Bytes)
		copy(ctBuf[i*cp.Ciphertext:], cts[i].Bytes)
	}

	ssBuf := make([]byte, count*cp.SharedSecret)

	if err := code.HQCDecapsBatch(codeMode, ssBuf, ctBuf, skBuf, count); err != nil {
		return false, err
	}

	for i := 0; i < count; i++ {
		ssBytes := make([]byte, cp.SharedSecret)
		copy(ssBytes, ssBuf[i*cp.SharedSecret:(i+1)*cp.SharedSecret])
		sss[i] = ssBytes
	}

	// Zeroise the skBuf — secret key material.
	zeroise(skBuf)

	return true, nil
}

// toCodeMode maps the hqc.Mode enum to the accel/code.Mode enum.
// They share bit patterns but we keep the mapping explicit so the
// two enums can evolve independently.
func toCodeMode(mode Mode) (code.Mode, error) {
	switch mode {
	case HQC128:
		return code.HQC128, nil
	case HQC192:
		return code.HQC192, nil
	case HQC256:
		return code.HQC256, nil
	default:
		return 0, ErrModeMismatch
	}
}

// readRandomSeeds returns `n` cryptographically secure random bytes.
// Uses the io.Reader pattern via a package-level reader so tests can
// inject a deterministic stream (see hqc_test.go's testRand).
//
// On the GPU dispatch path this is called once per batch with
// n = count * SeedEncaps.
var randSource io.Reader = systemRand{}

type systemRand struct{}

func (systemRand) Read(p []byte) (int, error) {
	return cryptorand.Read(p)
}

func readRandomSeeds(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(randSource, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// zeroise overwrites buf with zeros. Uses bytes.Repeat to defeat
// dead-store elimination — bytes.Repeat is an external call the
// compiler cannot inline-and-elide. The `bytes` package is imported
// at the top of this file just for this helper.
func zeroise(buf []byte) {
	if len(buf) == 0 {
		return
	}
	zero := bytes.Repeat([]byte{0}, len(buf))
	copy(buf, zero)
}
