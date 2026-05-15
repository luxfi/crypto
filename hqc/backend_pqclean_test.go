// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build hqc_pqclean

package hqc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

// hqcKatReader replicates PQClean's hqckatrng.c — a SHAKE-256-based
// PRNG seeded from a 48-byte entropy input with domain separator 0x01.
// The KAT harness installs this reader, runs keypair / enc, and prints
// the outputs; the resulting transcript's sha256 must match the
// upstream META.yml `nistkat-sha256` hash for the parameter set.
type hqcKatReader struct {
	shake sha3.ShakeHash
}

func newHQCKatReader(entropy []byte) *hqcKatReader {
	const domain = byte(0x01) // PRNG_DOMAIN from hqckatrng.c
	r := &hqcKatReader{shake: sha3.NewShake256()}
	_, _ = r.shake.Write(entropy)
	_, _ = r.shake.Write([]byte{domain})
	return r
}

func (r *hqcKatReader) Read(p []byte) (int, error) {
	return r.shake.Read(p)
}

// runHQCKAT replicates the body of PQClean's hqckat.c:
//   - seed `entropy = 0x00..0x2F`
//   - install KAT PRNG → squeeze 48-byte seed
//   - re-install KAT PRNG with that seed
//   - run keypair + enc + dec
//   - emit the same plaintext block hqckat.c prints to stdout
//
// The returned string is fed to sha256 and compared with
// nistkat-sha256 from the upstream META.yml.
func runHQCKAT(t *testing.T, mode Mode) string {
	t.Helper()

	// Step 1: build the 48-byte entropy input 0x00..0x2F.
	entropy := make([]byte, 48)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	// Step 2: first install — squeeze 48-byte `seed`.
	r1 := newHQCKatReader(entropy)
	seed := make([]byte, 48)
	if _, err := io.ReadFull(r1, seed); err != nil {
		t.Fatalf("kat seed squeeze failed: %v", err)
	}

	// Step 3: second install with `seed` as entropy. This reader is
	// the entropy source for keypair + enc.
	r2 := newHQCKatReader(seed)

	// Step 4: keypair.
	sk, err := KeyGen(mode, r2)
	if err != nil {
		t.Fatalf("KAT keygen: %v", err)
	}
	pk := sk.Pub
	// Step 5: encapsulate (same reader is consumed by enc).
	ct, ssEnc, err := Encapsulate(pk, r2)
	if err != nil {
		t.Fatalf("KAT encapsulate: %v", err)
	}
	// Step 6: decapsulate must match.
	ssDec, err := Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("KAT decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatalf("KAT round-trip ss mismatch")
	}

	// Step 7: emit the same plaintext hqckat.c produces.
	var buf strings.Builder
	fmt.Fprintf(&buf, "count = 0\n")
	fmt.Fprintf(&buf, "seed = %s\n", strings.ToUpper(hex.EncodeToString(seed)))
	fmt.Fprintf(&buf, "pk = %s\n", strings.ToUpper(hex.EncodeToString(pk.Bytes)))
	fmt.Fprintf(&buf, "sk = %s\n", strings.ToUpper(hex.EncodeToString(sk.Bytes)))
	fmt.Fprintf(&buf, "ct = %s\n", strings.ToUpper(hex.EncodeToString(ct.Bytes)))
	fmt.Fprintf(&buf, "ss = %s\n", strings.ToUpper(hex.EncodeToString(ssEnc)))
	return buf.String()
}

// TestKAT_HQC128 — sha256 of the KAT transcript must equal the
// nistkat-sha256 field of PQClean's
// crypto_kem/hqc-128/META.yml.
func TestKAT_HQC128(t *testing.T) {
	const wantHex = "74290ad7a789c01aa92cd7f72f1b5ba5fa30a58294cdf2df52b9c76c3aafba3b"
	got := sha256.Sum256([]byte(runHQCKAT(t, HQC128)))
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHex {
		t.Fatalf("HQC-128 KAT sha256 mismatch\nwant %s\n got %s", wantHex, gotHex)
	}
}

// TestKAT_HQC192 — sha256 must equal the nistkat-sha256 from
// crypto_kem/hqc-192/META.yml.
func TestKAT_HQC192(t *testing.T) {
	const wantHex = "771c5e421c4eea951850d5883e2329c40783a3c0f363d8dc8e1be7c4026d1ab7"
	got := sha256.Sum256([]byte(runHQCKAT(t, HQC192)))
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHex {
		t.Fatalf("HQC-192 KAT sha256 mismatch\nwant %s\n got %s", wantHex, gotHex)
	}
}

// TestKAT_HQC256 — sha256 must equal the nistkat-sha256 from
// crypto_kem/hqc-256/META.yml.
func TestKAT_HQC256(t *testing.T) {
	const wantHex = "e89c520e1ac615ecf6923f211569177c536a89bf94bebf85bb263528282092c4"
	got := sha256.Sum256([]byte(runHQCKAT(t, HQC256)))
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHex {
		t.Fatalf("HQC-256 KAT sha256 mismatch\nwant %s\n got %s", wantHex, gotHex)
	}
}

// TestRoundTrip_AllModes confirms encapsulate(pk) → decapsulate(sk) ss
// matches across all three parameter sets, using a non-KAT (random)
// seed.
func TestRoundTrip_AllModes(t *testing.T) {
	for _, mode := range []Mode{HQC128, HQC192, HQC256} {
		t.Run(MustParamsFor(mode).String(), func(t *testing.T) {
			seed := bytes.Repeat([]byte{0x42}, 128)
			r := newHQCKatReader(seed)
			sk, err := KeyGen(mode, r)
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			r2 := newHQCKatReader(append([]byte{0xAA}, seed...))
			ct, ssEnc, err := Encapsulate(sk.Pub, r2)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			ssDec, err := Decapsulate(sk, ct)
			if err != nil {
				t.Fatalf("decapsulate: %v", err)
			}
			if !bytes.Equal(ssEnc, ssDec) {
				t.Fatalf("ss mismatch\nenc %x\ndec %x", ssEnc, ssDec)
			}
			if len(ssEnc) != MustParamsFor(mode).SharedSecretSize {
				t.Fatalf("ss size = %d, want %d", len(ssEnc), MustParamsFor(mode).SharedSecretSize)
			}
		})
	}
}

// TestDeterminism — the precompile correctness depends on this: same
// (seed, op) produces byte-identical outputs.
func TestDeterminism(t *testing.T) {
	for _, mode := range []Mode{HQC128, HQC192, HQC256} {
		t.Run(MustParamsFor(mode).String(), func(t *testing.T) {
			seed := bytes.Repeat([]byte{0x37}, 96)

			sk1, err := KeyGen(mode, newHQCKatReader(seed))
			if err != nil {
				t.Fatalf("keygen1: %v", err)
			}
			sk2, err := KeyGen(mode, newHQCKatReader(seed))
			if err != nil {
				t.Fatalf("keygen2: %v", err)
			}
			if !bytes.Equal(sk1.Pub.Bytes, sk2.Pub.Bytes) {
				t.Fatalf("non-deterministic pk:\n  pk1 = %x\n  pk2 = %x",
					sk1.Pub.Bytes[:32], sk2.Pub.Bytes[:32])
			}
			if !bytes.Equal(sk1.Bytes, sk2.Bytes) {
				t.Fatalf("non-deterministic sk:\n  sk1 = %x\n  sk2 = %x",
					sk1.Bytes[:32], sk2.Bytes[:32])
			}

			encSeed := bytes.Repeat([]byte{0x71}, 128)
			ct1, ss1, err := Encapsulate(sk1.Pub, newHQCKatReader(encSeed))
			if err != nil {
				t.Fatalf("enc1: %v", err)
			}
			ct2, ss2, err := Encapsulate(sk1.Pub, newHQCKatReader(encSeed))
			if err != nil {
				t.Fatalf("enc2: %v", err)
			}
			if !bytes.Equal(ct1.Bytes, ct2.Bytes) {
				t.Fatalf("non-deterministic ct (load-bearing for precompile)")
			}
			if !bytes.Equal(ss1, ss2) {
				t.Fatalf("non-deterministic ss")
			}
		})
	}
}

// TestPQCleanDecapsulate_ModeMismatch — sk for one parameter set, ct
// for another, must be refused at the Go layer (we cannot feed a
// truncated/oversized ct to PQClean's HQC-N decap or it would read
// past the buffer).
func TestPQCleanDecapsulate_ModeMismatch(t *testing.T) {
	sk, err := KeyGen(HQC128, newHQCKatReader(bytes.Repeat([]byte{0x01}, 96)))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ct, _, err := Encapsulate(sk.Pub, newHQCKatReader(bytes.Repeat([]byte{0x02}, 64)))
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	// Pretend ct is HQC-256 and run decap with HQC-128 sk.
	ct256 := &Ciphertext{Mode: HQC256, Bytes: ct.Bytes}
	if _, err := Decapsulate(sk, ct256); !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("want ErrModeMismatch, got %v", err)
	}
}

// String helper for subtests.
func (p *Params) String() string {
	switch p.Mode {
	case HQC128:
		return "HQC-128"
	case HQC192:
		return "HQC-192"
	case HQC256:
		return "HQC-256"
	}
	return "HQC-?"
}
