package secp256k1

import (
	"crypto/rand"
	"testing"
)

func TestBatchVerifyMatchesScalar(t *testing.T) {
	n := BatchThreshold + 4

	pubs := make([][]byte, n)
	msgs := make([][]byte, n)
	sigs := make([][]byte, n)

	for i := 0; i < n; i++ {
		seckey := make([]byte, 32)
		for {
			if _, err := rand.Read(seckey); err != nil {
				t.Fatal(err)
			}
			// Reject zero key (decred rejects).
			any := false
			for _, b := range seckey {
				if b != 0 {
					any = true
					break
				}
			}
			if any {
				break
			}
		}

		// Derive pubkey via Sign roundtrip on a known msg.
		msg := make([]byte, 32)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(msg, seckey)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		pub, err := RecoverPubkey(msg, sig)
		if err != nil {
			t.Fatalf("RecoverPubkey: %v", err)
		}

		// Drop recovery byte for VerifySignature.
		sig64 := sig[:64]

		pubs[i] = pub
		msgs[i] = msg
		sigs[i] = sig64
	}

	got := BatchVerifySignature(pubs, msgs, sigs)
	for i := range got {
		if !got[i] {
			t.Errorf("batch[%d] reported invalid", i)
		}
		if VerifySignature(pubs[i], msgs[i], sigs[i]) != got[i] {
			t.Errorf("batch/scalar disagree at %d", i)
		}
	}
}
