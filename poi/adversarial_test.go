package poi

import (
	"testing"
)

// Adversarial (red-team) tests mirroring the Rust battery — each attack the soundness theorems
// forbid is exercised against the canonical Go verifier the chain consumes.

// THE KILLER: a forger crafts C' = A·B + Δ with Δ orthogonal to a GUESSED challenge r1, so
// Freivalds passes for r1 — but the real challenge is beacon-derived and unpredictable, so a fresh
// r2 catches it. This is why OpeningSeed binds blockhash(commitBlock): the prover cannot pre-fit.
func TestAttack_PreFitChallenge(t *testing.T) {
	a := NewMat(1, 1, []int64{3})
	n := 4
	b := NewMat(1, n, []int64{5, -7, 11, -2})
	honest := ExactMatmul(a, b)
	r1 := []uint64{1000, 2000, 3000, 4000} // the attacker's guess
	forged := NewMat(1, n, append([]int64(nil), honest.Data...))
	forged.Data[0] += int64(r1[1]) // Δ = [r1[1], -r1[0], 0, 0], so Δ·r1 = 0
	forged.Data[1] -= int64(r1[0])
	if !Verify(a, b, forged, r1) {
		t.Fatal("forgery must survive the GUESSED challenge r1 (the premise of the attack)")
	}
	r2 := []uint64{217, 999983, 31337, 42} // a beacon-fresh challenge the attacker can't predict
	if Verify(a, b, forged, r2) {
		t.Fatal("the forgery must be CAUGHT by a challenge the attacker could not predict")
	}
}

// A griefer's fabricated opening that was never committed under the honest root cannot prove fraud:
// CheckOpening reports not-included, so the gate's provesFraud (= included && !ok) is false.
func TestAttack_GrieferCannotFrame(t *testing.T) {
	s := uint64(0x6717)
	a := randMat(2, 4, &s)
	b := randMat(4, 2, &s)
	honest := NewTranscript()
	honest.CommitClaimed(a, b, ExactMatmul(a, b)) // the honest prover's root
	fake := ExactMatmul(a, b)
	fake.Data[0]++
	// the griefer encodes an opening over the honest root but with the fabricated C
	enc := EncodeOpening(honest.Root(), []byte("beacon"), Opening{Index: 0, A: a, B: b, C: fake, Proof: nil})
	included, ok, err := CheckOpening(enc, 2)
	if err != nil {
		t.Fatalf("CheckOpening: %v", err)
	}
	if included { // fabricated C is not the committed leaf → not included → cannot slash
		t.Fatal("a fabricated opening must NOT be included under the honest root")
	}
	_ = ok
}

// The wire decoder must be robust: arbitrary/truncated/oversized frames error, never panic.
func TestAttack_WireFuzz(t *testing.T) {
	seeds := []uint64{1, 2, 3, 7, 99, 12345, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF}
	for _, sd := range seeds {
		s := sd
		// pseudo-random byte frames of varied length
		for _, n := range []int{0, 1, 5, 33, 64, 200, 1000} {
			buf := make([]byte, n)
			for i := range buf {
				s = s*6364136223846793005 + 1442695040888963407
				buf[i] = byte(s >> 56)
			}
			// must not panic; an error or a clean (false,false) is acceptable.
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("DecodeOpening panicked on fuzzed frame (seed=%d len=%d): %v", sd, n, r)
					}
				}()
				_, _, _ = CheckOpening(buf, 2)
			}()
		}
	}
}

// A frame declaring an over-large matrix is rejected (bounds allocation, not OOM).
func TestAttack_OversizedDimsRejected(t *testing.T) {
	// hand-build a frame: root(32) index(8) beaconLen(4)=0 then A header rows=cols=MaxOpeningDim+1
	buf := make([]byte, 32+8+4)
	// A header
	big := uint32(MaxOpeningDim + 1)
	hdr := make([]byte, 8)
	hdr[0] = byte(big >> 24)
	hdr[1] = byte(big >> 16)
	hdr[2] = byte(big >> 8)
	hdr[3] = byte(big)
	copy(hdr[4:], hdr[0:4])
	buf = append(buf, hdr...)
	if _, _, err := CheckOpening(buf, 2); err == nil {
		t.Fatal("an over-large matrix dimension must be rejected")
	}
}
