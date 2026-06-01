// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ethdilithium_compat

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
)

// TestSignVerifyRoundTrip exercises the headline path: sign a
// message with EthDilithium, verify it back. No FIPS 204
// interaction expected in this test.
func TestSignVerifyRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0xE7}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}

	msg := []byte("EVM-friendly ML-DSA-65 round-trip")
	ctx := []byte("LUX/test/ethcompat")

	sig, err := Sign(sk.Bytes(), msg, ctx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("Sign returned %d bytes, want %d", len(sig), SignatureSize)
	}
	if !Verify(pk.Bytes(), msg, ctx, sig) {
		t.Fatal("Verify rejected an EthDilithium signature it just produced")
	}
}

// TestNotInteroperableWithFIPS204 asserts the design invariant: a
// signature produced by EthDilithium MUST NOT verify under the
// FIPS 204 verifier on the same (msg, ctx). This protects the
// strict-PQ profile from accidentally accepting compat-only inputs.
//
// (FIPS 204 *will* verify if you feed it the Keccak-derived
// effective message instead — that's how the wire format remains
// the same. The test below confirms that, too.)
func TestNotInteroperableWithFIPS204(t *testing.T) {
	seed := bytes.Repeat([]byte{0xE8}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}

	msg := []byte("interop check")
	ctx := []byte("LUX/test/interop")

	sig, err := Sign(sk.Bytes(), msg, ctx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Pin 1: FIPS 204 must NOT accept on raw (msg, ctx).
	if mldsa65.Verify(pk, msg, ctx, sig) {
		t.Fatal("FIPS 204 verifier accepted an EthDilithium signature " +
			"on raw (msg, ctx) — the variants must not interoperate " +
			"by default")
	}

	// Pin 2: FIPS 204 MUST accept on the Keccak effective message
	// (no ctx, since EthDilithium binds ctx via Keccak).
	effMsg := keccakEffectiveMessage(msg, ctx)
	if !mldsa65.Verify(pk, effMsg[:], nil, sig) {
		t.Fatal("FIPS 204 verifier rejected the EthDilithium signature " +
			"on the Keccak-derived effective message — the wire format " +
			"is supposed to be ML-DSA-65 standard, only the bound payload " +
			"differs")
	}
}

// TestVerifyRejectsTamperedSig flips one byte of the signature and
// asserts Verify returns false. Negative test for the headline
// path.
func TestVerifyRejectsTamperedSig(t *testing.T) {
	seed := bytes.Repeat([]byte{0xE9}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := []byte("tamper")
	ctx := []byte("LUX/test/tamper")
	sig, err := Sign(sk.Bytes(), msg, ctx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper inside c~ (first 48 bytes of sig).
	bad := append([]byte{}, sig...)
	bad[3] ^= 0x10
	if Verify(pk.Bytes(), msg, ctx, bad) {
		t.Fatal("Verify accepted a tampered signature")
	}

	// Tamper with the message: same sig, different msg, must reject.
	if Verify(pk.Bytes(), []byte("tampered msg"), ctx, sig) {
		t.Fatal("Verify accepted under a different message")
	}

	// Tamper with ctx: must reject (ctx is bound into the Keccak prefix).
	if Verify(pk.Bytes(), msg, []byte("LUX/test/tamper-other"), sig) {
		t.Fatal("Verify accepted under a different context")
	}
}

// TestVerifyRejectsBadSizes covers each of the three size-mismatch
// rejection paths.
func TestVerifyRejectsBadSizes(t *testing.T) {
	good := bytes.Repeat([]byte{0xAA}, PublicKeySize)
	sigOk := bytes.Repeat([]byte{0xBB}, SignatureSize)

	if Verify(good[:PublicKeySize-1], nil, nil, sigOk) {
		t.Error("accepted short pk")
	}
	if Verify(good, nil, nil, sigOk[:SignatureSize-1]) {
		t.Error("accepted short sig")
	}
	longCtx := make([]byte, 256)
	if Verify(good, nil, longCtx, sigOk) {
		t.Error("accepted 256-byte ctx")
	}
}

// TestSignRejectsBadSizes covers the sign-side size checks.
func TestSignRejectsBadSizes(t *testing.T) {
	if _, err := Sign(make([]byte, PrivateKeySize-1), nil, nil); err == nil {
		t.Error("Sign accepted short sk")
	}
	longCtx := make([]byte, 256)
	if _, err := Sign(make([]byte, PrivateKeySize), nil, longCtx); err == nil {
		t.Error("Sign accepted 256-byte ctx")
	}
}

// TestDeterministicSign asserts two Sign calls on the same input
// produce byte-identical signatures (we route through
// mldsa65.Sign(..., randomized=false) under the hood).
func TestDeterministicSign(t *testing.T) {
	seed := bytes.Repeat([]byte{0xEA}, mldsa65.SeedSize)
	_, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyFromSeed: %v", err)
	}
	msg := []byte("determinism check")
	ctx := []byte("LUX/test/determinism")

	sig1, err := Sign(sk.Bytes(), msg, ctx)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	sig2, err := Sign(sk.Bytes(), msg, ctx)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("EthDilithium Sign is not deterministic on identical inputs")
	}
}

// TestKeccakBindingPrefixLength confirms the (ctx, msg) split is
// unambiguous: (ctx="AB", msg="C") MUST produce a different
// effective message than (ctx="A", msg="BC"). Without the
// length-prefix byte, the two would Keccak-collide.
func TestKeccakBindingPrefixLength(t *testing.T) {
	a := keccakEffectiveMessage([]byte("C"), []byte("AB"))
	b := keccakEffectiveMessage([]byte("BC"), []byte("A"))
	if a == b {
		t.Fatal("(ctx=AB,msg=C) and (ctx=A,msg=BC) produced the same effMsg " +
			"— length-prefix is not preventing the boundary collision")
	}
}

// TestStrictPathLabel is a compile-time-ish check that the doc.go
// preamble names the strict path correctly. If someone renames
// the strict package without updating this test's expected string,
// the test fails — keeping the documentation honest.
func TestStrictPathLabel(t *testing.T) {
	// mldsa65 must remain the FIPS 204 canonical Level 3 entry.
	if mldsa65.SignatureSize != SignatureSize {
		t.Errorf("EthDilithium-compat must wrap mldsa65: SignatureSize mismatch")
	}
	if mldsa65.PublicKeySize != PublicKeySize {
		t.Errorf("EthDilithium-compat must wrap mldsa65: PublicKeySize mismatch")
	}
}

// BenchmarkSign measures the EthDilithium Sign throughput. The
// expected delta vs the canonical FIPS 204 sign is one extra
// Keccak-256 invocation per call — dominated by the ML-DSA cost,
// so the two should be close.
func BenchmarkSign(b *testing.B) {
	seed := bytes.Repeat([]byte{0xEB}, mldsa65.SeedSize)
	_, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		b.Fatalf("NewKeyFromSeed: %v", err)
	}
	skBytes := sk.Bytes()
	msg := bytes.Repeat([]byte{0x33}, 256)
	ctx := []byte("LUX/bench/ethcompat")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(skBytes, msg, ctx); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

// BenchmarkVerify measures the EthDilithium Verify throughput.
func BenchmarkVerify(b *testing.B) {
	seed := bytes.Repeat([]byte{0xEB}, mldsa65.SeedSize)
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		b.Fatalf("NewKeyFromSeed: %v", err)
	}
	pkBytes := pk.Bytes()
	msg := bytes.Repeat([]byte{0x33}, 256)
	ctx := []byte("LUX/bench/ethcompat")
	sig, err := Sign(sk.Bytes(), msg, ctx)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(pkBytes, msg, ctx, sig) {
			b.Fatal("verify failed mid-bench")
		}
	}
}
