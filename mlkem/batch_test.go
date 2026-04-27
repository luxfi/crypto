package mlkem

import (
	"bytes"
	"testing"
)

func TestBatchEncapDecap(t *testing.T) {
	for _, mode := range []Mode{MLKEM512, MLKEM768, MLKEM1024} {
		t.Run(mode.String(), func(t *testing.T) {
			n := BatchThreshold + 2
			pubs := make([]*PublicKey, n)
			privs := make([]*PrivateKey, n)
			for i := 0; i < n; i++ {
				pub, priv, err := GenerateKey(mode)
				if err != nil {
					t.Fatal(err)
				}
				pubs[i] = pub
				privs[i] = priv
			}

			cts, sss, err := BatchEncapsulate(pubs)
			if err != nil {
				t.Fatal(err)
			}
			if len(cts) != n || len(sss) != n {
				t.Fatalf("len(cts)=%d len(sss)=%d, want %d", len(cts), len(sss), n)
			}

			recovered, err := BatchDecapsulate(privs, cts)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < n; i++ {
				if !bytes.Equal(recovered[i], sss[i]) {
					t.Errorf("shared secret mismatch at %d", i)
				}
			}
		})
	}
}

func TestBatchEmpty(t *testing.T) {
	cts, sss, err := BatchEncapsulate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cts != nil || sss != nil {
		t.Fatal("expected nil/nil for empty input")
	}
}
