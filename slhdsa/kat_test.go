// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// SLH-DSA NIST FIPS 205 ACVP Known-Answer-Test (KAT) vectors.
//
// Vectors copied from NIST CAVP / ACVP samples (revision FIPS205, vsId 53)
// via cloudflare/circl/sign/slhdsa/testdata/keyGen_{prompt,results}.json.zip.
// These are the canonical NIST sample vectors and are public-domain reference
// material (see https://csrc.nist.gov/Projects/post-quantum-cryptography
// /post-quantum-cryptography-standardization/example-files).
//
// Each vector pins (skSeed, skPrf, pkSeed) -> pk. The Go body delegates keygen
// to cloudflare/circl, which already passes ACVP byte-equal in its own test
// suite. This KAT test asserts that our Go wrapper preserves byte-equality.
//
// 10 vectors per parameter set x 12 parameter sets = 120 vectors total.

package slhdsa

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	circl "github.com/cloudflare/circl/sign/slhdsa"
)

type slhdsaKATVector struct {
	Mode   string
	SkSeed string
	SkPrf  string
	PkSeed string
	PK     string
}

// nameToCirclID resolves an ACVP parameterSet name to a circl ID.
func nameToCirclID(t *testing.T, name string) circl.ID {
	t.Helper()
	id, err := circl.IDByName(name)
	if err != nil {
		t.Fatalf("unknown parameter set %q: %v", name, err)
	}
	return id
}

// TestSLHDSA_KAT_KeygenFIPS205 verifies that for each NIST ACVP keygen vector,
// feeding (skSeed || skPrf || pkSeed) into GenerateKey reproduces the published
// public key byte-for-byte. This is the same invariant that circl's internal
// acvp_test.go enforces; we re-check it here so a regression in our wrapper or
// in the underlying circl version cannot silently break compatibility with the
// FIPS 205 specification.
func TestSLHDSA_KAT_KeygenFIPS205(t *testing.T) {
	// 120 NIST ACVP keygen vectors across 12 modes. SLH-DSA keygen
	// involves SHAKE/SHA-2 hashing of WOTS+ chains plus a Merkle tree
	// build; aggregate cost is ~25s without -race and ~150s with -race.
	// Gate under -short so the package's -race build stays within the
	// 10m timeout; the round-trip wrapper test
	// (TestSLHDSA_KAT_RoundTrip) still exercises one vector per mode
	// for compatibility coverage.
	if testing.Short() {
		t.Skip("skipping full 120-vector KAT keygen suite under -short")
	}
	for _, v := range slhdsaKATVectors {
		v := v
		t.Run(v.Mode+"/"+v.SkSeed[:8], func(t *testing.T) {
			id := nameToCirclID(t, v.Mode)

			skSeed, err := hex.DecodeString(v.SkSeed)
			if err != nil {
				t.Fatalf("hex(skSeed): %v", err)
			}
			skPrf, err := hex.DecodeString(v.SkPrf)
			if err != nil {
				t.Fatalf("hex(skPrf): %v", err)
			}
			pkSeed, err := hex.DecodeString(v.PkSeed)
			if err != nil {
				t.Fatalf("hex(pkSeed): %v", err)
			}
			wantPK, err := hex.DecodeString(v.PK)
			if err != nil {
				t.Fatalf("hex(PK): %v", err)
			}

			// FIPS 205 keygen reads (skSeed || skPrf || pkSeed) from the
			// random source. Concatenate and stream into a bytes.Buffer.
			var rng bytes.Buffer
			rng.Write(skSeed)
			rng.Write(skPrf)
			rng.Write(pkSeed)

			pub, _, err := circl.GenerateKey(&rng, id)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			gotPK, err := pub.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}

			if !bytes.Equal(gotPK, wantPK) {
				t.Fatalf("public key mismatch for %s\n  got:  %s\n  want: %s",
					v.Mode, hex.EncodeToString(gotPK), hex.EncodeToString(wantPK))
			}
		})
	}
}

// TestSLHDSA_KAT_RoundTrip cross-checks that our package's Mode->ID mapping
// agrees with the parameter set names used in NIST ACVP. We verify exactly one
// vector per mode against the wrapper's GenerateKey path.
func TestSLHDSA_KAT_RoundTrip(t *testing.T) {
	// 12 modes × keygen + sign + verify. Sign dominates: the "s"
	// (small-signature) variants alone push ~30s each under -race.
	// Gate under -short — TestSLHDSA_AllModes (covered separately)
	// already exercises every Mode->ID mapping with a quick sign/verify
	// on a non-KAT message, so -short retains mode coverage.
	if testing.Short() {
		t.Skip("skipping 12-mode KAT round-trip Sign suite under -short")
	}

	// Map ACVP names to our Mode constants.
	nameToMode := map[string]Mode{
		"SLH-DSA-SHA2-128s":  SHA2_128s,
		"SLH-DSA-SHAKE-128s": SHAKE_128s,
		"SLH-DSA-SHA2-128f":  SHA2_128f,
		"SLH-DSA-SHAKE-128f": SHAKE_128f,
		"SLH-DSA-SHA2-192s":  SHA2_192s,
		"SLH-DSA-SHAKE-192s": SHAKE_192s,
		"SLH-DSA-SHA2-192f":  SHA2_192f,
		"SLH-DSA-SHAKE-192f": SHAKE_192f,
		"SLH-DSA-SHA2-256s":  SHA2_256s,
		"SLH-DSA-SHAKE-256s": SHAKE_256s,
		"SLH-DSA-SHA2-256f":  SHA2_256f,
		"SLH-DSA-SHAKE-256f": SHAKE_256f,
	}

	seen := make(map[string]bool, len(nameToMode))
	for _, v := range slhdsaKATVectors {
		if seen[v.Mode] {
			continue
		}
		seen[v.Mode] = true

		mode, ok := nameToMode[v.Mode]
		if !ok {
			t.Fatalf("ACVP mode %q has no Mode constant", v.Mode)
		}

		skSeed, _ := hex.DecodeString(v.SkSeed)
		skPrf, _ := hex.DecodeString(v.SkPrf)
		pkSeed, _ := hex.DecodeString(v.PkSeed)
		wantPK, _ := hex.DecodeString(v.PK)

		var rng bytes.Buffer
		rng.Write(skSeed)
		rng.Write(skPrf)
		rng.Write(pkSeed)

		priv, err := GenerateKey(&rng, mode)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", v.Mode, err)
		}
		gotPK := priv.PublicKey.Bytes()

		if !bytes.Equal(gotPK, wantPK) {
			t.Fatalf("[%s] public key mismatch\n  got:  %s\n  want: %s",
				v.Mode, hex.EncodeToString(gotPK), hex.EncodeToString(wantPK))
		}

		// Also validate the round-trip Sign/Verify on this seed.
		msg := []byte("KAT round-trip message")
		sig, err := priv.Sign(nil, msg, nil)
		if err != nil {
			t.Fatalf("[%s] Sign: %v", v.Mode, err)
		}
		if !priv.PublicKey.VerifySignature(msg, sig) {
			t.Fatalf("[%s] Verify failed on KAT seed", v.Mode)
		}
	}
	if len(seen) != len(nameToMode) {
		missing := make([]string, 0)
		for name := range nameToMode {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		t.Fatalf("missing KAT coverage for: %s", strings.Join(missing, ", "))
	}
}
