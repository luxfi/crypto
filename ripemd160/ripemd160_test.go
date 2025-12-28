package ripemd160

import (
	"encoding/hex"
	"testing"
)

func TestSum160Vectors(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
	}
	for _, c := range cases {
		got := Sum160([]byte(c.in))
		want, _ := hex.DecodeString(c.want)
		if string(got[:]) != string(want) {
			t.Errorf("Sum160(%q) = %x; want %s", c.in, got, c.want)
		}
	}
}

func TestNewIncremental(t *testing.T) {
	h := New()
	h.Write([]byte("a"))
	h.Write([]byte("bc"))
	got := h.Sum(nil)
	want, _ := hex.DecodeString("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
	if string(got) != string(want) {
		t.Errorf("incremental got %x want %x", got, want)
	}
}
