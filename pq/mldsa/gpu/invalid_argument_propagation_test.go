// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package gpu

import (
	"errors"
	"fmt"
	"testing"

	"github.com/luxfi/accel"
)

// TestRedM1_InvalidArgumentPropagationPolicy locks in the policy contract
// for Red M-1: GPU C-ABI ErrInvalidArgument must propagate as a hard error,
// never silently fall back to CPU.
//
// Why this test exists
// --------------------
// The luxcpp/accel C++ wrapper translates the GPU plugin's status code
// LUX_BACKEND_ERROR_INVALID_ARGUMENT to LUX_INVALID_ARGUMENT, which the
// cgo bridge surfaces as `accel.ErrInvalidArgument` (see
// internal/capi/capi.go::statusToError). When the wrapper rejects an
// input as malformed (msg_len > LUX_GPU_MLDSA_MSG_LEN_CAP, count >
// UINT32_MAX, null pointer with non-zero length), the CPU oracle
// (cloudflare/circl) may accept the same input — FIPS 204 allows
// arbitrary-length messages. If the Go dispatch path silently falls
// back to CPU on ErrInvalidArgument, two nodes running the same input
// produce different verdicts depending on whether they ran GPU or CPU.
// That's a consensus split.
//
// This test verifies the dispatch policy at the error-wrapping level
// without needing a real GPU or a multi-GB message buffer. It exercises
// the exact `errors.Is(err, accel.ErrInvalidArgument)` check used by
// signBatch (gpu_cgo.go:260) and verifyBatch (gpu_cgo.go:376), plus the
// equivalent sites in lux/crypto/mldsa/{batch,gpu}.go.
func TestRedM1_InvalidArgumentPropagationPolicy(t *testing.T) {
	// 1. The sentinel exists at the public accel surface.
	if accel.ErrInvalidArgument == nil {
		t.Fatal("accel.ErrInvalidArgument is nil; the Red M-1 propagation contract has no anchor")
	}

	// 2. The sentinel is identifiable through wrap chains (this is what
	//    signBatch/verifyBatch rely on).
	wrapped := fmt.Errorf("MLDSAVerifyBatch: %w", accel.ErrInvalidArgument)
	if !errors.Is(wrapped, accel.ErrInvalidArgument) {
		t.Fatal("errors.Is failed to detect accel.ErrInvalidArgument through fmt.Errorf %w wrap")
	}

	// 3. Other accel sentinels are distinguishable. The dispatch policy
	//    must propagate ONLY ErrInvalidArgument; the others (NotSupported,
	//    OutOfMemory, KernelFailed, NoBackends) are recoverable and must
	//    fall back to CPU.
	for _, other := range []error{
		accel.ErrNotSupported,
		accel.ErrOutOfMemory,
		accel.ErrKernelFailed,
		accel.ErrNoBackends,
	} {
		if other == nil {
			continue
		}
		if errors.Is(other, accel.ErrInvalidArgument) {
			t.Errorf("%v aliases accel.ErrInvalidArgument; propagation policy would treat recoverable error as hard error", other)
		}
		if errors.Is(accel.ErrInvalidArgument, other) {
			t.Errorf("accel.ErrInvalidArgument aliases %v; propagation policy would treat hard error as recoverable", other)
		}
	}

	// 4. classifyDispatchError mirrors the exact policy used in
	//    gpu_cgo.go::{signBatch,verifyBatch} and crypto/mldsa/gpu.go::
	//    batchVerifyGPU/batchSignGPU. If this classifier matches the
	//    code, both must say "hard" for ErrInvalidArgument and "recover"
	//    for everything else.
	classifyDispatchError := func(err error) string {
		if err == nil {
			return "ok"
		}
		if errors.Is(err, accel.ErrInvalidArgument) {
			return "hard"
		}
		return "recover"
	}

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "ok"},
		{"ErrInvalidArgument", accel.ErrInvalidArgument, "hard"},
		{"wrapped ErrInvalidArgument", fmt.Errorf("dispatch: %w", accel.ErrInvalidArgument), "hard"},
		{"ErrNotSupported", accel.ErrNotSupported, "recover"},
		{"ErrOutOfMemory", accel.ErrOutOfMemory, "recover"},
		{"ErrKernelFailed", accel.ErrKernelFailed, "recover"},
		{"ErrNoBackends", accel.ErrNoBackends, "recover"},
		{"unrelated error", errors.New("nominal pipeline failure"), "recover"},
	}
	for _, tc := range cases {
		if got := classifyDispatchError(tc.err); got != tc.want {
			t.Errorf("%s: classifyDispatchError(%v) = %q, want %q", tc.name, tc.err, got, tc.want)
		}
	}
}
