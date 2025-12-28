package sha256

import (
	stdsha256 "crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSum256(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, c := range cases {
		got := Sum256([]byte(c.in))
		want, _ := hex.DecodeString(c.want)
		if string(got[:]) != string(want) {
			t.Errorf("Sum256(%q) = %x; want %s", c.in, got, c.want)
		}
	}
}

func TestSum256BatchMatchesScalar(t *testing.T) {
	inputs := make([][]byte, BatchThreshold+4)
	for i := range inputs {
		inputs[i] = []byte("v" + string(rune('a'+i%26)))
	}
	got := Sum256Batch(inputs)
	for i, in := range inputs {
		want := stdsha256.Sum256(in)
		if got[i] != want {
			t.Errorf("batch[%d] mismatch", i)
		}
	}
}
