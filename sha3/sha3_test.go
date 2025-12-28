package sha3

import (
	"encoding/hex"
	"testing"
)

func TestSum256Vectors(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
		{"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
	}
	for _, c := range cases {
		got := Sum256([]byte(c.in))
		want, _ := hex.DecodeString(c.want)
		if string(got[:]) != string(want) {
			t.Errorf("Sum256(%q) = %x; want %s", c.in, got, c.want)
		}
	}
}

func TestSum512Vectors(t *testing.T) {
	got := Sum512([]byte("abc"))
	want, _ := hex.DecodeString("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
	if string(got[:]) != string(want) {
		t.Errorf("Sum512(abc) = %x; want %x", got, want)
	}
}

func TestShake128(t *testing.T) {
	out := make([]byte, 32)
	ShakeSum128(out, []byte("abc"))
	if hex.EncodeToString(out) == "" {
		t.Fatal("ShakeSum128 produced empty output")
	}
}
