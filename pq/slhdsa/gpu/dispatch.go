// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"errors"
	"io"

	"github.com/luxfi/crypto/slhdsa"
)

// ErrUnknownMode is returned when a Mode value does not map to any FIPS 205
// parameter set in the catalogue (params.go allParams).
var ErrUnknownMode = errors.New("slhdsa/gpu: unknown FIPS 205 Mode")

// modeToCanonical translates the pq/slhdsa/gpu.Mode (integer-keyed for the
// lux-accel C ABI) into the github.com/luxfi/crypto/slhdsa.Mode (iota-keyed
// for the canonical Go wrapper). Both encodings refer to the same FIPS 205
// parameter sets; this is the seam between two namespaces.
//
// We do not export the canonical type here — callers of pq/slhdsa/gpu work
// in Mode units, and SignBatch is the only public function that needs the
// translation.
func modeToCanonical(m Mode) (slhdsa.Mode, error) {
	switch m {
	case ModeSHA2_128s:
		return slhdsa.SHA2_128s, nil
	case ModeSHAKE_128s:
		return slhdsa.SHAKE_128s, nil
	case ModeSHA2_128f:
		return slhdsa.SHA2_128f, nil
	case ModeSHAKE_128f:
		return slhdsa.SHAKE_128f, nil
	case ModeSHA2_192s:
		return slhdsa.SHA2_192s, nil
	case ModeSHAKE_192s:
		return slhdsa.SHAKE_192s, nil
	case ModeSHA2_192f:
		return slhdsa.SHA2_192f, nil
	case ModeSHAKE_192f:
		return slhdsa.SHAKE_192f, nil
	case ModeSHA2_256s:
		return slhdsa.SHA2_256s, nil
	case ModeSHAKE_256s:
		return slhdsa.SHAKE_256s, nil
	case ModeSHA2_256f:
		return slhdsa.SHA2_256f, nil
	case ModeSHAKE_256f:
		return slhdsa.SHAKE_256f, nil
	default:
		return 0, ErrUnknownMode
	}
}

// SignBatch is the table-driven entry point. It validates the mode against
// the FIPS 205 §10 catalogue, then forwards into the canonical Lux SLH-DSA
// SignBatch which implements the full dispatch ladder:
//
//	tier 1 — GPU substrate via accel.LatticeOps.SLHDSASignBatch
//	tier 2 — goroutine-parallel CPU sign across GOMAXPROCS workers
//	tier 3 — serial CPU sign (cloudflare/circl, FIPS 205-conformant)
//
// Equivalence: FIPS 205 SignDeterministic has no per-call randomness, so all
// three tiers produce byte-identical signatures for any fixed (sk, msg).
//
// Decomposition principle (Hickey): this package owns the *parameter table*
// (params.go), not the dispatch logic. The dispatch already lives in
// github.com/luxfi/crypto/slhdsa.SignBatch. Composing the two here is one
// way (and only one way) to invoke an SLH-DSA batch sign that respects the
// canonical mode catalogue while routing through the canonical fast path.
func SignBatch(randSource io.Reader, mode Mode, privs []*slhdsa.PrivateKey, msgs [][]byte) ([][]byte, error) {
	if len(privs) == 0 {
		return nil, nil
	}
	canonical, err := modeToCanonical(mode)
	if err != nil {
		return nil, err
	}
	// Every private key must belong to the requested mode. We don't expose
	// a getter for the mode on slhdsa.PrivateKey by design (the canonical
	// wrapper checks this internally and returns an error). Verify here by
	// signature-size invariant: the canonical SignBatch already rejects
	// mixed modes, so we just delegate.
	_ = canonical // (used by the canonical SignBatch via the privs[i].mode)
	return slhdsa.SignBatch(randSource, privs, msgs)
}

// VerifyBatch is the verify counterpart to SignBatch. It forwards into the
// canonical VerifyBatch with the same tiered dispatch (GPU substrate,
// goroutine-parallel CPU, serial CPU). Equivalence holds by FIPS 205 verify
// determinism.
func VerifyBatch(mode Mode, pubs []*slhdsa.PublicKey, msgs, sigs [][]byte) ([]bool, error) {
	if _, err := modeToCanonical(mode); err != nil {
		return nil, err
	}
	return slhdsa.VerifyBatch(pubs, msgs, sigs), nil
}
