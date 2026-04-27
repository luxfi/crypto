package ed25519

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateSignVerify(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	sig := Sign(priv, msg)
	if !Verify(pub, msg, sig) {
		t.Fatal("Verify failed for valid signature")
	}
	if Verify(pub, []byte("other"), sig) {
		t.Fatal("Verify accepted wrong message")
	}
}

func TestNewKeyFromSeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv1, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv1, priv2) {
		t.Fatal("seed not deterministic")
	}

	_, err = NewKeyFromSeed(seed[:31])
	if err == nil {
		t.Fatal("expected error for short seed")
	}
}

func TestBatchVerifyMatchesScalar(t *testing.T) {
	n := BatchThreshold + 4
	pubs := make([]PublicKey, n)
	msgs := make([][]byte, n)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		pub, priv, err := GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		msgs[i] = []byte{byte(i), byte(i << 1)}
		sigs[i] = Sign(priv, msgs[i])
		pubs[i] = pub
	}

	got := BatchVerify(pubs, msgs, sigs)
	for i, g := range got {
		if !g {
			t.Errorf("batch[%d] reported invalid", i)
		}
		if Verify(pubs[i], msgs[i], sigs[i]) != g {
			t.Errorf("batch/scalar disagree at %d", i)
		}
	}

	// Flip one signature byte to ensure we report invalid.
	sigs[0][0] ^= 0xff
	got = BatchVerify(pubs, msgs, sigs)
	if got[0] {
		t.Fatal("batch accepted tampered signature")
	}
}
