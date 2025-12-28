// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"
)

//go:embed test_vectors.json
var officialVectors []byte

// kat is the schema of the BLAKE3 reference test_vectors.json file.
//
// Each case provides extended outputs (variable length); implementations
// must check that the first 32 bytes match the default-length output. The
// input is the repeating pattern 0,1,...,250,0,1,... truncated to input_len.
type kat struct {
	Key           string `json:"key"`
	ContextString string `json:"context_string"`
	Cases         []struct {
		InputLen   int    `json:"input_len"`
		Hash       string `json:"hash"`
		KeyedHash  string `json:"keyed_hash"`
		DeriveKey  string `json:"derive_key"`
	} `json:"cases"`
}

// genInput builds the 251-byte repeating pattern truncated to n.
func genInput(n int) []byte {
	in := make([]byte, n)
	for i := 0; i < n; i++ {
		in[i] = byte(i % 251)
	}
	return in
}

func TestOfficialKAT(t *testing.T) {
	var v kat
	if err := json.Unmarshal(officialVectors, &v); err != nil {
		t.Fatalf("decode test vectors: %v", err)
	}
	if got := len(v.Cases); got != 35 {
		t.Fatalf("expected 35 official vectors, got %d", got)
	}
	if len(v.Key) != 32 {
		t.Fatalf("key length: got %d want 32", len(v.Key))
	}

	keyBytes := []byte(v.Key)
	pass := 0

	for _, c := range v.Cases {
		in := genInput(c.InputLen)

		// 1) Default Hash: first 32 bytes of extended hash output.
		want, err := hex.DecodeString(c.Hash[:64])
		if err != nil {
			t.Fatalf("len=%d: bad hash hex: %v", c.InputLen, err)
		}
		got := Hash(in)
		if string(got[:]) != string(want) {
			t.Errorf("Hash(input_len=%d) = %x; want %s", c.InputLen, got, c.Hash[:64])
			continue
		}

		// 2) KeyedHash: first 32 bytes match.
		wantKeyed, err := hex.DecodeString(c.KeyedHash[:64])
		if err != nil {
			t.Fatalf("len=%d: bad keyed_hash hex: %v", c.InputLen, err)
		}
		gotKeyed, err := KeyedHash(keyBytes, in)
		if err != nil {
			t.Fatalf("KeyedHash(input_len=%d): %v", c.InputLen, err)
		}
		if string(gotKeyed[:]) != string(wantKeyed) {
			t.Errorf("KeyedHash(input_len=%d) = %x; want %s", c.InputLen, gotKeyed, c.KeyedHash[:64])
			continue
		}

		// 3) DeriveKey: KDF mode with hardcoded context — full 32 bytes.
		wantDK, err := hex.DecodeString(c.DeriveKey[:64])
		if err != nil {
			t.Fatalf("len=%d: bad derive_key hex: %v", c.InputLen, err)
		}
		gotDK := make([]byte, 32)
		DeriveKey(v.ContextString, in, gotDK)
		if string(gotDK) != string(wantDK) {
			t.Errorf("DeriveKey(input_len=%d) = %x; want %s", c.InputLen, gotDK, c.DeriveKey[:64])
			continue
		}

		pass++
	}

	if pass != 35 {
		t.Fatalf("KAT: %d/35 passed", pass)
	}
	t.Logf("KAT: %d/35 official BLAKE3 vectors PASS", pass)
}

func TestHashBatchMatchesScalar(t *testing.T) {
	inputs := [][]byte{
		nil,
		[]byte(""),
		[]byte("abc"),
		[]byte("hello world"),
		genInput(64),
		genInput(1024),
		genInput(4097),
	}
	got := HashBatch(inputs)
	for i, in := range inputs {
		want := Hash(in)
		if got[i] != want {
			t.Errorf("HashBatch[%d] = %x; want %x", i, got[i], want)
		}
	}
}

func TestHashBatchLargeMatchesScalar(t *testing.T) {
	// Cross BatchThreshold to exercise potential GPU path; the GPU stub
	// falls through to CPU but the routing should produce identical bytes.
	inputs := make([][]byte, BatchThreshold+8)
	for i := range inputs {
		inputs[i] = genInput((i*17)%513 + 1)
	}
	got := HashBatch(inputs)
	for i, in := range inputs {
		want := Hash(in)
		if got[i] != want {
			t.Errorf("HashBatch[%d] mismatch (len=%d)", i, len(in))
		}
	}
}

func TestNewIncrementalEqualsHash(t *testing.T) {
	in := genInput(2049)
	h := New()
	h.Write(in[:333])
	h.Write(in[333:1024])
	h.Write(in[1024:])
	got := h.Sum(nil)

	want := Hash(in)
	if string(got) != string(want[:]) {
		t.Errorf("incremental %x != contiguous %x", got, want)
	}
}

func TestConcat(t *testing.T) {
	got := Concat([]byte("hello"), []byte(" "), []byte("world"))
	want := Hash([]byte("hello world"))
	if got != want {
		t.Errorf("Concat = %x; want %x", got, want)
	}
}

func TestHashHex(t *testing.T) {
	// Sanity: HashHex of the empty string equals the canonical BLAKE3 hex
	// of "" from the reference suite (first 32 bytes).
	want := "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if got := HashHex(nil); got != want {
		t.Errorf("HashHex(nil) = %s; want %s", got, want)
	}
}

func TestReaderXOF(t *testing.T) {
	// XOF: first 32 bytes must equal Hash, and the second 32 bytes must
	// match the next 32 bytes of the extended output in the KAT.
	var v kat
	if err := json.Unmarshal(officialVectors, &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	c := v.Cases[0] // input_len=0
	r := Reader(nil)
	buf := make([]byte, 64)
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("XOF read: %v", err)
	}
	want, _ := hex.DecodeString(c.Hash[:128])
	if string(buf) != string(want) {
		t.Errorf("XOF(empty)[0:64] = %x; want %s", buf, c.Hash[:128])
	}
}

func TestKeyedHashRejectsBadKey(t *testing.T) {
	if _, err := KeyedHash(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("KeyedHash with 16-byte key: expected error")
	}
	if _, err := KeyedHash(make([]byte, 32), []byte("x")); err != nil {
		t.Fatalf("KeyedHash with 32-byte key: unexpected error: %v", err)
	}
}

func BenchmarkHash(b *testing.B) {
	in := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Hash(in)
	}
}

func BenchmarkHashBatch(b *testing.B) {
	inputs := make([][]byte, BatchThreshold)
	for i := range inputs {
		inputs[i] = make([]byte, 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashBatch(inputs)
	}
}
