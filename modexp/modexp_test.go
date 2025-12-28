package modexp

import "testing"

func TestIntCompiles(t *testing.T) {
	a := new(Int).SetInt64(2)
	b := new(Int).SetInt64(10)
	m := new(Int).SetInt64(1000)
	r := new(Int).Exp(a, b, m)
	if r.Cmp(new(Int).SetInt64(24)) != 0 {
		t.Errorf("2^10 mod 1000 = %v; want 24", r)
	}
}
