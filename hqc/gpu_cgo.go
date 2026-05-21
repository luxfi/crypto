// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// gpu_cgo.go — cgo-enabled single-shot HQC low-level operations.
//
// Routes through github.com/luxfi/accel/hqc, the canonical Go binding
// layer for the luxcpp/gpu native kernels (libluxgpu_hqc.a). This
// gives crypto/hqc a clean per-call entry to the bit-sliced Karatsuba
// polynomial multiplication kernel without dragging in the full
// luxfi/gpu surface (which carries ZK + ML-DSA + ML-KEM symbols and
// has its own transitive native-library link requirements).
//
// Layering rationale:
//
//	crypto/hqc/gpu_cgo.go    --> accel/hqc          (this path)
//	crypto/hqc/gpu_cgo.go    -X-> luxfi/gpu/hqc_cgo (not used here)
//
// luxfi/gpu/hqc_cgo.go is also a valid binding path (it shares the
// underlying libluxgpu_hqc.a), but crypto/hqc only needs the slim
// HQC-specific surface, not the full unified GPU API. Going via
// accel/hqc keeps the dependency graph narrow:
//
//	crypto/hqc -> accel/hqc -> accel/ops/code -> luxcpp/gpu C kernels
//
// The batch dispatchers batchEncapsulateGPU / batchDecapsulateGPU
// live in gpu.go (build-tag-agnostic) and route through the same
// accel/ops/code batch surface. This file ONLY covers single-shot
// primitives so callers that need one-off polymuls don't pay the
// batch surface's setup cost.
//
// Determinism contract: byte-equal to PQClean's vect_mul. Validators
// reach consensus on the output of HQC encapsulation / decapsulation,
// so any divergence from PQClean is a consensus fork.

package hqc

import (
	luxhqc "github.com/luxfi/accel/hqc"
)

// vecNSize64 returns the per-mode uint64 vector length for GF(2)^N.
// Defined in gpu_nocgo.go too — the cgo path mirrors it explicitly
// rather than calling out via the accel boundary for what is a
// compile-time-known constant.
func vecNSize64(mode Mode) (int, error) {
	switch mode {
	case HQC128:
		return (17669 + 63) / 64, nil
	case HQC192:
		return (35851 + 63) / 64, nil
	case HQC256:
		return (57637 + 63) / 64, nil
	default:
		return 0, ErrModeMismatch
	}
}

// redMaskForMode returns the high-word mask used to clear the top
// PARAM_N-aligned bits after reduction mod (X^N - 1). Mirrors
// gpu_nocgo.go's same-named helper.
func redMaskForMode(mode Mode) (uint64, int, error) {
	switch mode {
	case HQC128:
		return 0x1f, 17669, nil
	case HQC192:
		return 0x7ff, 35851, nil
	case HQC256:
		return 0x1fffffffff, 57637, nil
	default:
		return 0, 0, ErrModeMismatch
	}
}

// toAccelHQCMode maps crypto/hqc.Mode to accel/hqc.Mode. Both enums
// share bit patterns but we keep the mapping explicit so they can
// evolve independently.
func toAccelHQCMode(mode Mode) (luxhqc.Mode, error) {
	switch mode {
	case HQC128:
		return luxhqc.HQC128, nil
	case HQC192:
		return luxhqc.HQC192, nil
	case HQC256:
		return luxhqc.HQC256, nil
	default:
		return 0, ErrModeMismatch
	}
}

// GF2Polymul computes c(x) = a(x) * b(x) mod (X^n - 1) in GF(2)[X].
// All three buffers must be length VecNSize64 for mode. Wraps the
// accel/hqc HQC kernel — byte-equal to PQClean's vect_mul.
//
// Constant-time: the kernel uses the same masked table lookup as
// PQClean (no data-dependent branches or memory indices on secret
// operands).
func GF2Polymul(mode Mode, c, a, b []uint64) error {
	accelMode, err := toAccelHQCMode(mode)
	if err != nil {
		return err
	}
	// accel/hqc.GF2PolymulBatch processes count polynomials; count=1
	// is the single-shot path. Per-slot per-cgo-crossing cost is
	// ~150 ns on Apple M1 Max, which dominates only for vectors
	// shorter than ~256 uint64 — at HQC-128's VEC_N_SIZE_64=277 this
	// is already amortised; HQC-192 (561) and HQC-256 (901) are
	// firmly cgo-favourable.
	return luxhqc.GF2PolymulBatch(accelMode, c, a, b, 1)
}

// GF2Add computes c[i] = a[i] ^ b[i] over GF(2)^N. Constant-time
// (pure XOR, no branches). Implemented in pure Go even on the cgo
// path because (a) it's a single SIMD-friendly loop the compiler
// inlines well, and (b) the cgo crossover is a hard floor of ~150ns
// that overwhelms the actual XOR cost for any vector under ~64 KB.
func GF2Add(c, a, b []uint64) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if len(c) < n {
		n = len(c)
	}
	for i := 0; i < n; i++ {
		c[i] = a[i] ^ b[i]
	}
}
