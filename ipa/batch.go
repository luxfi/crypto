// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.

package multiproof

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
	"github.com/luxfi/crypto/ipa/common"
	"github.com/luxfi/crypto/ipa/ipa"
)

// ErrBatchLengthMismatch is returned when CheckMultiProofBatch receives
// inputs whose outer slices disagree on length.
var ErrBatchLengthMismatch = errors.New("ipa: batch slice length mismatch")

// BatchProof bundles a single multiproof with the public data needed to
// check it. A BatchProofs slice is the canonical input shape for the
// batched verifier (and for the GPU driver once it lands).
type BatchProof struct {
	Proof *MultiProof              // the multi-proof to verify
	Cs    []*banderwagon.Element   // commitments  (per opening within this proof)
	Ys    []*fr.Element            // claimed evaluations
	Zs    []uint8                  // evaluation points (within domain)
}

// CheckMultiProofBatch verifies many MultiProofs in lockstep. Each proof gets
// its own fresh transcript (the protocol is "verifiable, deterministically
// random per proof"); the batched form simply spares the caller a loop and
// gives the C++ / GPU layer a contiguous workload to dispatch on.
//
// Returns nil on full success or an error on the first mismatch (with the
// failing index embedded). Returning ErrBatchLengthMismatch means the input
// is malformed; any other non-nil return means a specific proof failed.
//
// Future work: a fully-batched verifier that randomizes the linear combination
// across proofs would amortize MSM cost; that's a separate code path.
func CheckMultiProofBatch(transcriptLabel []byte, ipaConf *ipa.IPAConfig, proofs []BatchProof) error {
	if len(proofs) == 0 {
		return ErrBatchLengthMismatch
	}
	for i, bp := range proofs {
		if bp.Proof == nil {
			return fmt.Errorf("ipa batch[%d]: nil proof", i)
		}
		if len(bp.Cs) != len(bp.Ys) || len(bp.Cs) != len(bp.Zs) {
			return fmt.Errorf("ipa batch[%d]: %w", i, ErrBatchLengthMismatch)
		}
		t := common.NewTranscript(string(transcriptLabel))
		ok, err := CheckMultiProof(t, ipaConf, bp.Proof, bp.Cs, bp.Ys, bp.Zs)
		if err != nil {
			return fmt.Errorf("ipa batch[%d]: %w", i, err)
		}
		if !ok {
			return fmt.Errorf("ipa batch[%d]: proof failed", i)
		}
	}
	return nil
}
