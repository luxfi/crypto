package bls

import "testing"

func TestBatchVerifyMatchesScalar(t *testing.T) {
	n := BatchThreshold + 4
	pks := make([]*PublicKey, n)
	msgs := make([][]byte, n)
	sigs := make([]*Signature, n)

	for i := 0; i < n; i++ {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatal(err)
		}
		pks[i] = sk.PublicKey()
		msgs[i] = []byte{byte(i), byte(i << 1), byte(i + 7)}
		sig, err := sk.Sign(msgs[i])
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig
	}

	got := BatchVerify(pks, msgs, sigs)
	for i := range got {
		if !got[i] {
			t.Errorf("batch[%d] reported invalid", i)
		}
		if Verify(pks[i], sigs[i], msgs[i]) != got[i] {
			t.Errorf("batch/scalar disagree at %d", i)
		}
	}

	// Tamper one signature: BLS signatures are bytes; flip one bit.
	tampered := SignatureToBytes(sigs[0])
	tampered[0] ^= 0x01
	bad, err := SignatureFromBytes(tampered)
	if err != nil {
		// Some bit-flips trip decompress validation, which is also a "false"
		// answer; in that case skip and try next.
		for i := 1; i < SignatureLen; i++ {
			tampered = SignatureToBytes(sigs[0])
			tampered[i] ^= 0x01
			bad, err = SignatureFromBytes(tampered)
			if err == nil {
				break
			}
		}
	}
	if err == nil && bad != nil {
		sigs[0] = bad
		got = BatchVerify(pks, msgs, sigs)
		if got[0] {
			t.Error("batch accepted tampered signature")
		}
	}
}

func TestBatchVerifyEmpty(t *testing.T) {
	got := BatchVerify(nil, nil, nil)
	if len(got) != 0 {
		t.Errorf("empty input returned len %d", len(got))
	}
}
