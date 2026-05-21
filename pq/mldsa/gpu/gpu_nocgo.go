// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package gpu

import (
	"runtime"
	"sync"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// newEngine returns the no-CGO engine. It satisfies the full engine
// interface using only pure-Go primitives — the NTT operations dispatch
// to ntt_cpu.go, and the sign/verify operations dispatch to the
// circl-backed wrappers in pq/mldsa/mldsa{44,65,87}.
//
// Batch operations exploit GOMAXPROCS via a worker pool so a no-CGO
// host still gets multi-core throughput. This is a real implementation,
// not a stub: callers that don't have CGO available still get the full
// FIPS 204 NTT and signing surface.
func newEngine() engine {
	return &cpuEngine{
		// Cap the worker count to a sane value to avoid contending
		// for the Go scheduler when batches are large.
		workers: capWorkers(runtime.GOMAXPROCS(0)),
	}
}

// cpuEngine is the no-CGO engine. All operations run on the CPU using
// pure-Go code. Batch operations are parallelised across GOMAXPROCS
// goroutines.
type cpuEngine struct {
	workers int
}

// available is false on a no-CGO build. The dispatcher treats this as
// "skip GPU threshold, just call the CPU path on the engine".
func (e *cpuEngine) available() bool { return false }

// backend returns the active backend name.
func (e *cpuEngine) backend() string { return "cpu" }

// nttForwardBatch runs forward NTT on every polynomial. Polynomials are
// chunked across e.workers goroutines so batches scale with cores.
func (e *cpuEngine) nttForwardBatch(polys []*[N]uint32) error {
	if len(polys) == 0 {
		return nil
	}
	parallelDo(len(polys), e.workers, func(i int) {
		NTTForwardCPU(polys[i])
	})
	return nil
}

// nttInverseBatch is the inverse of nttForwardBatch.
func (e *cpuEngine) nttInverseBatch(polys []*[N]uint32) error {
	if len(polys) == 0 {
		return nil
	}
	parallelDo(len(polys), e.workers, func(i int) {
		NTTInverseCPU(polys[i])
	})
	return nil
}

// polyMulBatch computes c[i] = a[i] * b[i] in R_q for each i.
func (e *cpuEngine) polyMulBatch(a, b, c []*[N]uint32) error {
	parallelDo(len(a), e.workers, func(i int) {
		out := PolyMulCPU(a[i], b[i])
		*c[i] = out
	})
	return nil
}

// signBatch dispatches per-element to the circl-backed wrappers in
// pq/mldsa/mldsa{44,65,87}. The element-level work is independent so
// the loop parallelises trivially. The cSHAKE context "LUX/FIPS204/
// MLDSA{44,65,87}/batch" is the empty string here because the wrapper
// itself does not require a specific context for batch signing;
// callers that need domain separation pass it through the wrapper API
// directly.
func (e *cpuEngine) signBatch(mode Mode, msgs, sks, sigs [][]byte) error {
	var sigErr error
	var errMu sync.Mutex
	parallelDo(len(msgs), e.workers, func(i int) {
		var sig []byte
		var err error
		switch mode {
		case ModeMLDSA44:
			sk := new(mldsa44.PrivateKey)
			if uerr := sk.UnmarshalBinary(sks[i]); uerr != nil {
				err = uerr
			} else {
				sig, err = mldsa44.Sign(sk, msgs[i], nil, false)
			}
		case ModeMLDSA65:
			sk := new(mldsa65.PrivateKey)
			if uerr := sk.UnmarshalBinary(sks[i]); uerr != nil {
				err = uerr
			} else {
				sig, err = mldsa65.Sign(sk, msgs[i], nil, false)
			}
		case ModeMLDSA87:
			sk := new(mldsa87.PrivateKey)
			if uerr := sk.UnmarshalBinary(sks[i]); uerr != nil {
				err = uerr
			} else {
				sig, err = mldsa87.Sign(sk, msgs[i], nil, false)
			}
		default:
			err = ErrInvalidMode
		}
		if err != nil {
			errMu.Lock()
			if sigErr == nil {
				sigErr = err
			}
			errMu.Unlock()
			return
		}
		copy(sigs[i], sig)
	})
	return sigErr
}

// verifyBatch dispatches per-element to the circl-backed wrappers.
func (e *cpuEngine) verifyBatch(mode Mode, msgs, sigs, pks [][]byte) ([]bool, error) {
	res := make([]bool, len(msgs))
	parallelDo(len(msgs), e.workers, func(i int) {
		switch mode {
		case ModeMLDSA44:
			pk := new(mldsa44.PublicKey)
			if err := pk.UnmarshalBinary(pks[i]); err != nil {
				res[i] = false
				return
			}
			res[i] = mldsa44.Verify(pk, msgs[i], nil, sigs[i])
		case ModeMLDSA65:
			pk := new(mldsa65.PublicKey)
			if err := pk.UnmarshalBinary(pks[i]); err != nil {
				res[i] = false
				return
			}
			res[i] = mldsa65.Verify(pk, msgs[i], nil, sigs[i])
		case ModeMLDSA87:
			pk := new(mldsa87.PublicKey)
			if err := pk.UnmarshalBinary(pks[i]); err != nil {
				res[i] = false
				return
			}
			res[i] = mldsa87.Verify(pk, msgs[i], nil, sigs[i])
		default:
			res[i] = false
		}
	})
	return res, nil
}

