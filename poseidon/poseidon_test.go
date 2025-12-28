// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

//go:embed testdata/poseidon2_t2_kat.json
var poseidon2KATJSON []byte

type kat struct {
	Width         int        `json:"width"`
	FullRounds    int        `json:"full_rounds"`
	PartialRounds int        `json:"partial_rounds"`
	SBox          int        `json:"sbox"`
	Cases         []katCase  `json:"kat"`
}

type katCase struct {
	InputHex  []string `json:"input_hex"`
	OutputHex []string `json:"output_hex"`
}

func loadPoseidonKAT(t *testing.T) *kat {
	t.Helper()
	var v kat
	if err := json.Unmarshal(poseidon2KATJSON, &v); err != nil {
		t.Fatalf("decode KAT: %v", err)
	}
	if v.Width != Width || v.FullRounds != FullRounds ||
		v.PartialRounds != PartialRounds || v.SBox != SBoxDegree {
		t.Fatalf("KAT params mismatch: got w=%d rF=%d rP=%d d=%d, want w=%d rF=%d rP=%d d=%d",
			v.Width, v.FullRounds, v.PartialRounds, v.SBox,
			Width, FullRounds, PartialRounds, SBoxDegree)
	}
	if len(v.Cases) < 10 {
		t.Fatalf("only %d KAT cases; need >= 10", len(v.Cases))
	}
	return &v
}

// hex32 parses a "0x..." hex string into a 32-byte array.
func hex32(t *testing.T, s string) [FieldSize]byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	if len(b) != FieldSize {
		t.Fatalf("expected %d bytes; got %d", FieldSize, len(b))
	}
	var out [FieldSize]byte
	copy(out[:], b)
	return out
}

// TestKATPermutation runs Poseidon2 t=2 against pre-computed KAT vectors
// (generated from gnark-crypto v0.20.1 directly).
func TestKATPermutation(t *testing.T) {
	v := loadPoseidonKAT(t)
	for i, c := range v.Cases {
		l := hex32(t, c.InputHex[0])
		r := hex32(t, c.InputHex[1])
		wantL := hex32(t, c.OutputHex[0])
		wantR := hex32(t, c.OutputHex[1])
		if err := Permutation2(&l, &r); err != nil {
			t.Fatalf("case %d: permutation: %v", i, err)
		}
		if l != wantL || r != wantR {
			t.Errorf("case %d:\n got  (%s, %s)\n want (%s, %s)",
				i,
				hex.EncodeToString(l[:]), hex.EncodeToString(r[:]),
				hex.EncodeToString(wantL[:]), hex.EncodeToString(wantR[:]))
		}
	}
	t.Logf("verified %d Poseidon2 t=2 permutation KAT cases", len(v.Cases))
}

func TestSum2Deterministic(t *testing.T) {
	in := make([]byte, 64)
	for i := range in {
		in[i] = byte(i)
	}
	a, err := Sum2(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sum2(in)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("Sum2 not deterministic: %x vs %x", a, b)
	}
}

func TestSum2RejectsNon32(t *testing.T) {
	_, err := Sum2([]byte{1, 2, 3})
	if err != ErrInvalidFieldSize {
		t.Errorf("expected ErrInvalidFieldSize; got %v", err)
	}
}

func TestSum2DistinctInputs(t *testing.T) {
	in1 := make([]byte, 32)
	in2 := make([]byte, 32)
	in2[0] = 1
	a, _ := Sum2(in1)
	b, _ := Sum2(in2)
	if a == b {
		t.Errorf("distinct inputs collide: %x", a)
	}
}
