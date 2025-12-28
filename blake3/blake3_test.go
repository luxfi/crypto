// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

//go:embed testdata/test_vectors.json
var testVectorsJSON []byte

// kat is the BLAKE3 official KAT structure (see test_vectors.json).
type kat struct {
	Key           string `json:"key"`
	ContextString string `json:"context_string"`
	Cases         []struct {
		InputLen     int    `json:"input_len"`
		Hash         string `json:"hash"`
		KeyedHash    string `json:"keyed_hash"`
		DeriveKey    string `json:"derive_key"`
	} `json:"cases"`
}

// kat251 generates the canonical BLAKE3 test input: a repeating sequence of
// 251 bytes (0..250) of length n (matches the upstream spec).
func kat251(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

// loadKAT parses the embedded test_vectors.json.
func loadKAT(t *testing.T) *kat {
	t.Helper()
	var v kat
	if err := json.Unmarshal(testVectorsJSON, &v); err != nil {
		t.Fatalf("decode test_vectors.json: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no test cases loaded")
	}
	return &v
}

// hexHead returns the first 64 hex chars (32 bytes) of a longer hex string.
func hexHead(s string) string {
	if len(s) < 64 {
		return s
	}
	return s[:64]
}

// Each test_vectors.json case stores a 131-byte hex output (longer XOF). The
// 32-byte digest matches the first 64 hex chars.
func TestKATHash(t *testing.T) {
	v := loadKAT(t)
	for _, c := range v.Cases {
		got := Sum256(kat251(c.InputLen))
		want := hexHead(c.Hash)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("hash[len=%d]\n got  %s\n want %s",
				c.InputLen, hex.EncodeToString(got[:]), want)
		}
	}
}

func TestKATKeyedHash(t *testing.T) {
	v := loadKAT(t)
	if len(v.Key) != KeySize {
		t.Fatalf("KAT key length = %d, want %d", len(v.Key), KeySize)
	}
	var key [KeySize]byte
	copy(key[:], v.Key)
	for _, c := range v.Cases {
		got := Keyed(key, kat251(c.InputLen))
		want := hexHead(c.KeyedHash)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("keyed[len=%d]\n got  %s\n want %s",
				c.InputLen, hex.EncodeToString(got[:]), want)
		}
	}
}

func TestKATDeriveKey(t *testing.T) {
	v := loadKAT(t)
	if !strings.HasPrefix(v.ContextString, "BLAKE3") {
		t.Fatalf("KAT context: %q", v.ContextString)
	}
	for _, c := range v.Cases {
		got := DeriveKey(v.ContextString, kat251(c.InputLen))
		want := hexHead(c.DeriveKey)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("derive[len=%d]\n got  %s\n want %s",
				c.InputLen, hex.EncodeToString(got[:]), want)
		}
	}
}

// TestKATXOF verifies the XOF output matches all 131 bytes of each KAT,
// not just the first 32. This exercises the streaming output path.
func TestKATXOF(t *testing.T) {
	v := loadKAT(t)
	for _, c := range v.Cases {
		want, err := hex.DecodeString(c.Hash)
		if err != nil {
			t.Fatalf("decode hash hex: %v", err)
		}
		got := make([]byte, len(want))
		Sum(got, kat251(c.InputLen))
		if hex.EncodeToString(got) != c.Hash {
			t.Errorf("xof[len=%d, out=%d bytes]\n got  %s\n want %s",
				c.InputLen, len(want), hex.EncodeToString(got), c.Hash)
		}
	}
}

// TestKATCount asserts we are exercising at least 10 KAT vectors per mode
// (acceptance criterion).
func TestKATCount(t *testing.T) {
	v := loadKAT(t)
	if len(v.Cases) < 10 {
		t.Errorf("only %d KAT cases; need >= 10", len(v.Cases))
	}
	t.Logf("running %d KAT cases (hash + keyed + derive_key + xof)", len(v.Cases))
}
