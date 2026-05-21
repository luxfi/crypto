// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package gpu

import (
	"runtime"
	"sync"

	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/internal/gpuhost"
	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// newEngine returns the CGO engine. When luxfi/accel reports a working
// GPU session, batch operations are dispatched to the accel Lattice ops
// surface (Metal / CUDA / WebGPU per host). When no GPU is available,
// the engine falls back to the same pure-Go CPU path the no-CGO build
// uses — so cgo=on builds never regress against cgo=off builds.
func newEngine() engine {
	e := &cgoEngine{
		workers: capWorkers(runtime.GOMAXPROCS(0)),
	}
	// Lazily probe the GPU. gpuhost.Available() initialises accel and
	// reports whether a session was created successfully. We cache the
	// answer; callers that need a re-probe can call (*Accelerator).
	// SetThresholds with sentinel values, but normal flow keeps the
	// session alive for the whole process.
	if gpuhost.Available() {
		e.sess = gpuhost.Session()
	}
	return e
}

// cgoEngine is the CGO engine. It owns no resources of its own — the
// accel session lifecycle is governed by crypto/internal/gpuhost — but
// it caches the resolved session pointer to avoid re-acquiring it on
// every batch call.
type cgoEngine struct {
	sess    *accel.Session
	workers int
}

// available reports whether a working accel session is available.
func (e *cgoEngine) available() bool {
	return e.sess != nil
}

// backend returns the active backend name from accel.
func (e *cgoEngine) backend() string {
	if e.sess == nil {
		return "cpu"
	}
	return e.sess.Backend().String()
}

// nttForwardBatch dispatches the whole batch to accel.LatticeOps.
// PolynomialNTT. Each polynomial is uploaded to a per-call tensor and
// the kernel runs over Z_q[X]/(X^256+1) with q=8380417.
//
// On any failure (allocation, kernel, sync) we fall back to the CPU
// path so the dispatcher's invariant ("batch always completes") holds.
func (e *cgoEngine) nttForwardBatch(polys []*[N]uint32) error {
	if e.sess == nil {
		return e.nttForwardBatchCPU(polys)
	}
	for _, p := range polys {
		if err := e.runNTT(e.sess.Lattice().PolynomialNTT, p); err != nil {
			return e.nttForwardBatchCPU(polys)
		}
	}
	return nil
}

func (e *cgoEngine) nttForwardBatchCPU(polys []*[N]uint32) error {
	parallelDo(len(polys), e.workers, func(i int) {
		NTTForwardCPU(polys[i])
	})
	return nil
}

// nttInverseBatch is the inverse of nttForwardBatch.
func (e *cgoEngine) nttInverseBatch(polys []*[N]uint32) error {
	if e.sess == nil {
		return e.nttInverseBatchCPU(polys)
	}
	for _, p := range polys {
		if err := e.runNTT(e.sess.Lattice().PolynomialINTT, p); err != nil {
			return e.nttInverseBatchCPU(polys)
		}
	}
	return nil
}

func (e *cgoEngine) nttInverseBatchCPU(polys []*[N]uint32) error {
	parallelDo(len(polys), e.workers, func(i int) {
		NTTInverseCPU(polys[i])
	})
	return nil
}

// runNTT uploads one polynomial to the GPU, dispatches the kernel, and
// downloads the result into the same slot. fn is one of PolynomialNTT
// or PolynomialINTT from the accel Lattice ops interface.
func (e *cgoEngine) runNTT(
	fn func(*accel.UntypedTensor, *accel.UntypedTensor, uint32) error,
	p *[N]uint32,
) error {
	in, err := accel.NewTensorWithData[uint32](e.sess, []int{N}, p[:])
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := accel.NewTensor[uint32](e.sess, []int{N})
	if err != nil {
		return err
	}
	defer out.Close()

	if err := fn(in.Untyped(), out.Untyped(), Q); err != nil {
		return err
	}
	if err := e.sess.Sync(); err != nil {
		return err
	}
	result, err := out.ToSlice()
	if err != nil {
		return err
	}
	if len(result) != N {
		return ErrInvalidLength
	}
	copy(p[:], result)
	// Keep tensor handles pinned until after Sync completes — the
	// canonical idiom for tensor lifetimes that cross the CGO boundary.
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)
	return nil
}

// polyMulBatch computes c[i] = a[i] * b[i] in R_q for each i. The accel
// path uses NTT(a) ⊙ NTT(b) → INTT in a single set of kernels.
func (e *cgoEngine) polyMulBatch(a, b, c []*[N]uint32) error {
	if e.sess == nil {
		return e.polyMulBatchCPU(a, b, c)
	}
	lat := e.sess.Lattice()
	for i := range a {
		aT, err := accel.NewTensorWithData[uint32](e.sess, []int{N}, a[i][:])
		if err != nil {
			return e.polyMulBatchCPU(a, b, c)
		}
		bT, err := accel.NewTensorWithData[uint32](e.sess, []int{N}, b[i][:])
		if err != nil {
			aT.Close()
			return e.polyMulBatchCPU(a, b, c)
		}
		cT, err := accel.NewTensor[uint32](e.sess, []int{N})
		if err != nil {
			aT.Close()
			bT.Close()
			return e.polyMulBatchCPU(a, b, c)
		}
		if err := lat.PolynomialMul(aT.Untyped(), bT.Untyped(), cT.Untyped(), Q); err != nil {
			aT.Close()
			bT.Close()
			cT.Close()
			return e.polyMulBatchCPU(a, b, c)
		}
		if err := e.sess.Sync(); err != nil {
			aT.Close()
			bT.Close()
			cT.Close()
			return e.polyMulBatchCPU(a, b, c)
		}
		result, err := cT.ToSlice()
		aT.Close()
		bT.Close()
		cT.Close()
		if err != nil {
			return e.polyMulBatchCPU(a, b, c)
		}
		if len(result) != N {
			return e.polyMulBatchCPU(a, b, c)
		}
		copy(c[i][:], result)
	}
	return nil
}

func (e *cgoEngine) polyMulBatchCPU(a, b, c []*[N]uint32) error {
	parallelDo(len(a), e.workers, func(i int) {
		out := PolyMulCPU(a[i], b[i])
		*c[i] = out
	})
	return nil
}

// signBatch dispatches to accel.LatticeOps.MLDSASignBatch when a GPU is
// available, else falls back to per-element CPU signing through the
// circl-backed wrappers. Mode is one of {2, 3, 5}; the accel ABI uses
// the same encoding so it passes straight through.
//
// All slices in the batch must use the FIPS 204-mandated key and signature
// sizes for the chosen mode; the function pads message length to the max
// across the batch (the accel ABI requires a uniform message width).
func (e *cgoEngine) signBatch(mode Mode, msgs, sks, sigs [][]byte) error {
	p, ok := ParamsFor(mode)
	if !ok {
		return ErrInvalidMode
	}
	if e.sess == nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}

	n := len(msgs)
	if n == 0 {
		return nil
	}
	msgWidth := maxLen(msgs)
	if msgWidth == 0 {
		// accel requires a non-empty msg tensor; widen to 1 byte so the
		// tensor allocation succeeds.
		msgWidth = 1
	}

	msgsPad := padBatch(msgs, msgWidth)
	sksPad, err := packExact(sks, p.PrivateKeySize)
	if err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	msgT, err := accel.NewTensorWithData[uint8](e.sess, []int{n, msgWidth}, msgsPad)
	if err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	defer msgT.Close()
	skT, err := accel.NewTensorWithData[uint8](e.sess, []int{n, p.PrivateKeySize}, sksPad)
	if err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	defer skT.Close()
	sigT, err := accel.NewTensor[uint8](e.sess, []int{n, p.SignatureSize})
	if err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	defer sigT.Close()

	if err := e.sess.Lattice().MLDSASignBatch(int(mode), msgT.Untyped(), skT.Untyped(), sigT.Untyped()); err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	if err := e.sess.Sync(); err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	flat, err := sigT.ToSlice()
	if err != nil {
		return e.signBatchCPU(mode, msgs, sks, sigs)
	}
	for i := 0; i < n; i++ {
		if len(sigs[i]) < p.SignatureSize {
			return ErrShapeMismatch
		}
		copy(sigs[i], flat[i*p.SignatureSize:(i+1)*p.SignatureSize])
	}
	return nil
}

// signBatchCPU is the per-element CPU fallback. Shared between the
// "GPU unavailable" and "GPU returned an error" branches.
func (e *cgoEngine) signBatchCPU(mode Mode, msgs, sks, sigs [][]byte) error {
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

// verifyBatch dispatches to accel.LatticeOps.MLDSAVerifyBatch when a GPU
// is available, else falls back to per-element CPU verification. The
// returned slice has one bool per input; deterministic per FIPS 204
// §5.3 so CPU and GPU produce identical accept/reject decisions.
func (e *cgoEngine) verifyBatch(mode Mode, msgs, sigs, pks [][]byte) ([]bool, error) {
	p, ok := ParamsFor(mode)
	if !ok {
		return nil, ErrInvalidMode
	}
	if e.sess == nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	n := len(msgs)
	if n == 0 {
		return nil, nil
	}
	msgWidth := maxLen(msgs)
	if msgWidth == 0 {
		msgWidth = 1
	}
	msgsPad := padBatch(msgs, msgWidth)
	sigsPad, err := packExact(sigs, p.SignatureSize)
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	pksPad, err := packExact(pks, p.PublicKeySize)
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}

	msgT, err := accel.NewTensorWithData[uint8](e.sess, []int{n, msgWidth}, msgsPad)
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	defer msgT.Close()
	sigT, err := accel.NewTensorWithData[uint8](e.sess, []int{n, p.SignatureSize}, sigsPad)
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	defer sigT.Close()
	pkT, err := accel.NewTensorWithData[uint8](e.sess, []int{n, p.PublicKeySize}, pksPad)
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	defer pkT.Close()
	resT, err := accel.NewTensor[uint8](e.sess, []int{n})
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	defer resT.Close()

	if err := e.sess.Lattice().MLDSAVerifyBatch(int(mode), msgT.Untyped(), sigT.Untyped(), pkT.Untyped(), resT.Untyped()); err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	if err := e.sess.Sync(); err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	raw, err := resT.ToSlice()
	if err != nil {
		return e.verifyBatchCPU(mode, msgs, sigs, pks)
	}
	out := make([]bool, n)
	for i := 0; i < n; i++ {
		out[i] = raw[i] != 0
	}
	return out, nil
}

func (e *cgoEngine) verifyBatchCPU(mode Mode, msgs, sigs, pks [][]byte) ([]bool, error) {
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

// maxLen returns the largest length in batch, or 0 for an empty batch.
func maxLen(batch [][]byte) int {
	w := 0
	for _, b := range batch {
		if len(b) > w {
			w = len(b)
		}
	}
	return w
}

// padBatch flattens a ragged batch of messages into a dense [n * width]
// byte buffer, zero-padding each row on the right. accel's batch tensor
// API requires a uniform row width.
func padBatch(batch [][]byte, width int) []byte {
	out := make([]byte, len(batch)*width)
	for i, m := range batch {
		copy(out[i*width:], m)
	}
	return out
}

// packExact verifies that every element of batch has exactly `size`
// bytes and returns the densely-packed concatenation. If any element
// has a wrong length, returns ErrShapeMismatch — accel batch entry
// points require strict size match for key and signature tensors.
func packExact(batch [][]byte, size int) ([]byte, error) {
	out := make([]byte, len(batch)*size)
	for i, b := range batch {
		if len(b) != size {
			return nil, ErrShapeMismatch
		}
		copy(out[i*size:], b)
	}
	return out, nil
}
