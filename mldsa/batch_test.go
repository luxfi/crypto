package mldsa

import (
	"crypto/rand"
	"testing"
)

func TestBatchVerifyMatchesScalar(t *testing.T) {
	for _, mode := range []Mode{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(map[Mode]string{MLDSA44: "44", MLDSA65: "65", MLDSA87: "87"}[mode], func(t *testing.T) {
			n := BatchThreshold + 2
			pubs := make([]*PublicKey, n)
			msgs := make([][]byte, n)
			sigs := make([][]byte, n)
			for i := 0; i < n; i++ {
				priv, err := GenerateKey(rand.Reader, mode)
				if err != nil {
					t.Fatal(err)
				}
				pubs[i] = priv.PublicKey
				msgs[i] = []byte{byte(i), byte(i + 1)}
				sig, err := priv.SignCtx(rand.Reader, msgs[i], nil)
				if err != nil {
					t.Fatal(err)
				}
				sigs[i] = sig
			}

			got := BatchVerify(pubs, msgs, sigs)
			for i := range got {
				if !got[i] {
					t.Errorf("batch[%d] reported invalid", i)
				}
				if pubs[i].VerifySignature(msgs[i], sigs[i]) != got[i] {
					t.Errorf("batch/scalar disagree at %d", i)
				}
			}
		})
	}
}
