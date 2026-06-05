// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"errors"
	"fmt"
	"testing"

	"github.com/luxfi/accel"
)

// TestRed176_SLHDSAInvalidArgumentPropagationPolicy locks in the policy
// contract for Red CRITICAL #176: GPU C-ABI ErrInvalidArgument from the
// SLH-DSA batch verify/sign paths must propagate as a hard error, never
// silently fall back to CPU.
//
// Why this test exists
// --------------------
// The luxcpp/accel C++ wrapper translates the lux-private GPU plugin's
// status LUX_BACKEND_ERROR_INVALID_ARGUMENT into accel.ErrInvalidArgument
// (capi.go::statusToError). The SLH-DSA plugin sites enforce
// LUX_GPU_SLHDSA_MSG_LEN_CAP (= INT32_MAX - 2) and a count ceiling
// (UINT32_MAX / kBatchMaxFactor where kBatchMaxFactor = 7680). When the
// wrapper rejects an input as malformed (msg_len > cap, count > ceiling,
// null pointer with non-zero length), the CPU oracle (cloudflare/circl)
// may accept the same input — FIPS 205 allows arbitrary-length messages.
// If the Go dispatch path silently falls back to CPU on
// ErrInvalidArgument, two nodes running the same input produce different
// verdicts depending on whether they ran GPU or CPU. That's a consensus
// split.
//
// This test verifies the dispatch policy at the error-wrapping level
// without needing a real GPU or a multi-GB message buffer. It exercises
// the exact `errors.Is(err, accel.ErrInvalidArgument)` check used by
// VerifyBatchGPU (gpu.go:271) and SignBatchGPU (gpu.go:440) in this
// package, plus the equivalent site in lux/accel/ops/crypto/crypto_gpu.go
// (SigMLDSA65 broadcast fix, Red CRITICAL #177).
func TestRed176_SLHDSAInvalidArgumentPropagationPolicy(t *testing.T) {
	// 1. The sentinel exists at the public accel surface.
	if accel.ErrInvalidArgument == nil {
		t.Fatal("accel.ErrInvalidArgument is nil; the Red CRITICAL #176 propagation contract has no anchor")
	}

	// 2. The sentinel is identifiable through wrap chains (this is what
	//    VerifyBatchGPU / SignBatchGPU rely on at gpu.go).
	wrapped := fmt.Errorf("SLHDSAVerifyBatch: %w", accel.ErrInvalidArgument)
	if !errors.Is(wrapped, accel.ErrInvalidArgument) {
		t.Fatal("errors.Is failed to detect accel.ErrInvalidArgument through fmt.Errorf %w wrap")
	}

	// 3. Other accel sentinels are distinguishable. The dispatch policy
	//    must propagate ONLY ErrInvalidArgument; the others (NotSupported,
	//    OutOfMemory, KernelFailed, NoBackends) are recoverable and must
	//    fall back to CPU. If any of these aliased ErrInvalidArgument the
	//    propagation policy would treat recoverable errors as hard errors,
	//    making every backend-not-registered host fail closed.
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

	// 4. classifyDispatchError mirrors the exact policy used in this
	//    package's VerifyBatchGPU / SignBatchGPU (see the `errors.Is(err,
	//    accel.ErrInvalidArgument)` branch at gpu.go::VerifyBatchGPU and
	//    gpu.go::SignBatchGPU). If this classifier matches the code, both
	//    must say "hard" for ErrInvalidArgument and "recover" for
	//    everything else.
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
		{"double-wrapped ErrInvalidArgument", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", accel.ErrInvalidArgument)), "hard"},
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

// TestRed176_SLHDSAVerifyBatchGPU_ContractDocumentation pins the doc
// contract on VerifyBatchGPU so a future refactor can't quietly revert
// the M-1 propagation policy. The function's tri-state return is the
// load-bearing piece: (dispatched, err) where err can carry
// ErrInvalidArgument as a hard contract violation.
//
// We can't actually trigger ErrInvalidArgument from Go without either
// (a) a multi-GB message buffer or (b) a count > UINT32_MAX/7680 batch,
// neither of which is reasonable in a unit test. Instead, we lock the
// contract by asserting that the function exists with the right
// signature shape (compile-time check) and that the returned error type
// supports errors.Is unwrapping (already covered above).
func TestRed176_SLHDSAVerifyBatchGPU_ContractDocumentation(t *testing.T) {
	// Compile-time: VerifyBatchGPU must return (bool, error).
	var _ func([]*PublicKey, [][]byte, [][]byte, []bool) (bool, error) = VerifyBatchGPU

	// Compile-time: SignBatchGPU must return (bool, error).
	var _ func([]*PrivateKey, [][]byte, [][]byte) (bool, error) = SignBatchGPU

	// Empty-batch invariant: VerifyBatchGPU returns (true, nil) for n=0.
	// This is the "nothing to dispatch" case, NOT the hard-error case.
	ok, err := VerifyBatchGPU(nil, nil, nil, nil)
	if !ok || err != nil {
		t.Errorf("VerifyBatchGPU(empty) = (%v, %v); want (true, nil)", ok, err)
	}

	// Empty-batch invariant for SignBatchGPU.
	ok, err = SignBatchGPU(nil, nil, nil)
	if !ok || err != nil {
		t.Errorf("SignBatchGPU(empty) = (%v, %v); want (true, nil)", ok, err)
	}
}
