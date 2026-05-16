// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SLH-DSA / Comet (FIPS 205) GPU dispatch.
//
// Mirrors crypto/mldsa/gpu.go. The dispatch boundary is the same:
//
//	backend.Resolve(gpuhost.Available(), false) → backend.GPU
//	  ⇒ accel.LatticeOps.SLHDSAVerifyBatch on the shared session
//	  ⇒ luxcpp/lux-accel C API lux_slhdsa_verify_batch
//	  ⇒ (when a backend plugin registers a strong symbol)
//	    luxcpp/crypto/slhdsa/gpu/{metal,cuda}/ kernel substrate
//	  ⇒ otherwise the weak stub returns LUX_NO_BACKEND and we fall back
//	    to per-element CPU verify (cloudflare/circl, FIPS 205-conformant).
//
// Equivalence is by construction: the GPU and CPU paths both call into
// FIPS-205-conformant verifiers, and the dispatcher reports the same
// accept/reject decision per element. See TestSLHDSABatchEquivalence_CPU_GPU
// for the byte-level guarantee.

package slhdsa

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// modeToCAPI maps our Mode enum to the integer mode the lux-accel C ABI
// expects (see luxcpp/crypto/slhdsa/c-abi/c_slhdsa.cpp + luxcpp/lux-accel
// c_api.h SLH-DSA section). Only the 'f' (fast) variants are wired through
// GPU dispatch — the 's' (small) variants stay CPU-only since the FIPS-205
// catalogue lists them as bandwidth-optimised, not throughput-optimised.
func modeToCAPI(m Mode) (int, bool) {
	switch m {
	case SHA2_128f:
		return 2, true
	case SHA2_192f:
		return 3, true
	case SHA2_256f:
		return 5, true
	case SHAKE_128f:
		return 12, true
	case SHAKE_192f:
		return 13, true
	case SHAKE_256f:
		return 15, true
	default:
		return 0, false
	}
}

// VerifyBatchGPU verifies a batch of SLH-DSA signatures on the GPU when a
// GPU backend is present and the parameter set is one of the 'f' variants
// (see modeToCAPI). Returns (dispatched, error):
//   - dispatched=true means the GPU path produced `out`; len(out) == len(pubs).
//   - dispatched=false means the GPU is unavailable for this batch and the
//     caller MUST fall back to per-element CPU verify. `out` is untouched.
//
// All inputs MUST share the same Mode. Mixed batches must be partitioned by
// the caller (the GPU kernel dispatches one mode per launch).
//
// This function never panics on a transport-level failure; it returns
// (false, nil) so the call site falls back transparently to CPU. The single
// signal that something is materially broken is when len(pubs) is inconsistent
// with len(msgs) or len(sigs) — that returns (false, nil) too.
func VerifyBatchGPU(pubs []*PublicKey, msgs, sigs [][]byte, out []bool) (bool, error) {
	if len(pubs) == 0 {
		return true, nil
	}
	if len(msgs) != len(pubs) || len(sigs) != len(pubs) || len(out) != len(pubs) {
		return false, nil
	}

	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	// All entries must share the same parameter set.
	mode := pubs[0].mode
	capiMode, ok := modeToCAPI(mode)
	if !ok {
		return false, nil
	}
	for i := 1; i < len(pubs); i++ {
		if pubs[i].mode != mode {
			return false, nil
		}
	}

	pkSize := GetPublicKeySize(mode)
	sigSize := GetSignatureSize(mode)
	if pkSize == 0 || sigSize == 0 {
		return false, nil
	}

	n := len(pubs)

	// Find the maximum message width — the batch tensor pads short msgs
	// to the widest entry's length. Width >= 1 so the [N,W] tensor is
	// well-formed even when every input is empty.
	width := 1
	for _, m := range msgs {
		if len(m) > width {
			width = len(m)
		}
	}

	mFlat := make([]uint8, n*width)
	for i, m := range msgs {
		copy(mFlat[i*width:(i+1)*width], m)
	}
	pFlat := make([]uint8, n*pkSize)
	for i, p := range pubs {
		if len(p.publicKey) != pkSize {
			return false, nil
		}
		copy(pFlat[i*pkSize:(i+1)*pkSize], p.publicKey)
	}
	sFlat := make([]uint8, n*sigSize)
	for i, s := range sigs {
		if len(s) != sigSize {
			return false, nil
		}
		copy(sFlat[i*sigSize:(i+1)*sigSize], s)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, width}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	sT, err := accel.NewTensorWithData[uint8](sess, []int{n, sigSize}, sFlat)
	if err != nil {
		return false, nil
	}
	defer sT.Close()
	pT, err := accel.NewTensorWithData[uint8](sess, []int{n, pkSize}, pFlat)
	if err != nil {
		return false, nil
	}
	defer pT.Close()
	rT, err := accel.NewTensor[uint8](sess, []int{n})
	if err != nil {
		return false, nil
	}
	defer rT.Close()

	if err := sess.Lattice().SLHDSAVerifyBatch(capiMode, mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped()); err != nil {
		return false, nil
	}
	bytes, err := rT.ToSlice()
	if err != nil {
		return false, nil
	}
	for i, b := range bytes {
		out[i] = b == 1
	}
	return true, nil
}

// VerifyBatch verifies a batch of SLH-DSA signatures. It transparently
// dispatches to GPU when available (and the parameter set is a 'f' variant);
// otherwise it falls back to a per-element CPU loop. Either way the returned
// slice is dense (one bool per input, in order).
//
// Inputs must all share the same Mode; otherwise this function returns the
// CPU per-element result of each public key verifying against its own mode.
func VerifyBatch(pubs []*PublicKey, msgs, sigs [][]byte) []bool {
	n := len(pubs)
	out := make([]bool, n)
	if n != len(msgs) || n != len(sigs) {
		return out
	}

	if dispatched, _ := VerifyBatchGPU(pubs, msgs, sigs, out); dispatched {
		return out
	}

	// CPU fallback: per-element verify. Each PublicKey carries its own
	// mode, so mixed-mode batches degrade gracefully.
	for i := range pubs {
		out[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
	}
	return out
}
