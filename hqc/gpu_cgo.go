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
// The native kernels are linked only when built with -tags=lux_hqc_native
// (accel v1.2+). Without that tag the accel surface returns
// code.ErrNativeHQCUnavailable; GF2Polymul below detects this and falls
// back to the tag-neutral pure-Go implementation in
// gpu_polymul_purego.go, which is byte-for-byte identical to PQClean.
// That keeps the default cgo build (CI, pure-Go deployments) correct and
// link-clean without the native HQC library.
//
// The batch dispatchers batchEncapsulateGPU / batchDecapsulateGPU
// live in gpu.go (build-tag-agnostic) and route through the same
// accel/ops/code batch surface, with the same fallback semantics. This
// file ONLY covers single-shot primitives so callers that need one-off
// polymuls don't pay the batch surface's setup cost.
//
// Determinism contract: byte-equal to PQClean's vect_mul. Validators
// reach consensus on the output of HQC encapsulation / decapsulation,
// so any divergence from PQClean is a consensus fork.

package hqc

import (
	"errors"

	luxhqc "github.com/luxfi/accel/hqc"
	"github.com/luxfi/accel/ops/code"
)

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
// When the accel native HQC library is not linked (the default build,
// without -tags=lux_hqc_native), accel returns
// code.ErrNativeHQCUnavailable; we then fall back to the pure-Go
// Karatsuba path (gpu_polymul_purego.go), which is also byte-equal to
// PQClean. Either way the result is consensus-identical.
//
// Constant-time: both the native kernel and the pure-Go fallback use
// the same masked table lookup as PQClean (no data-dependent branches
// or memory indices on secret operands).
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
	if err := luxhqc.GF2PolymulBatch(accelMode, c, a, b, 1); err != nil {
		if errors.Is(err, code.ErrNativeHQCUnavailable) {
			// Native kernel not linked — use the pure-Go path, which is
			// byte-for-byte identical to PQClean's vect_mul.
			return polymulGo(mode, c, a, b)
		}
		return err
	}
	return nil
}

// GF2Add computes c[i] = a[i] ^ b[i] over GF(2)^N. Constant-time
// (pure XOR, no branches). Implemented in pure Go even on the cgo
// path because (a) it's a single SIMD-friendly loop the compiler
// inlines well, and (b) the cgo crossover is a hard floor of ~150ns
// that overwhelms the actual XOR cost for any vector under ~64 KB.
// Delegates to the shared helper in gpu_polymul_purego.go.
func GF2Add(c, a, b []uint64) {
	gf2AddGo(c, a, b)
}
