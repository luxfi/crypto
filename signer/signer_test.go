package signer

import (
	"context"
	"testing"

	"github.com/luxfi/crypto/threshold"
)

func TestSigner(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("Test message for Lux consensus signing")

	t.Run("BLS", func(t *testing.T) {
		sig, err := signer.SignBLS(message)
		if err != nil {
			t.Fatalf("BLS sign failed: %v", err)
		}
		if !signer.VerifyBLS(message, sig) {
			t.Fatalf("BLS verification failed")
		}
		if signer.VerifyBLS([]byte("wrong"), sig) {
			t.Fatalf("BLS should not verify wrong message")
		}
		t.Logf("BLS signature size: %d bytes", len(sig))
		t.Logf("BLS public key size: %d bytes", len(signer.GetBLSPublicKey()))
	})

	t.Run("ThresholdSeed", func(t *testing.T) {
		seed := signer.ThresholdSeed()
		if len(seed) != 32 {
			t.Fatalf("Threshold seed should be 32 bytes, got %d", len(seed))
		}
	})

	// Uninitialized threshold state exercises ONLY the crypto/threshold
	// interface — no concrete scheme. The BLS-backed integration test lives
	// in luxfi/threshold/scheme/bls (importing crypto/signer from there keeps
	// crypto free of any luxfi/threshold dependency — no module cycle).
	t.Run("ThresholdNotInitialized", func(t *testing.T) {
		if signer.HasThresholdKey() {
			t.Fatal("Signer should not have threshold key initially")
		}
		if signer.ThresholdSchemeID() != threshold.SchemeUnknown {
			t.Fatalf("Expected SchemeUnknown, got %v", signer.ThresholdSchemeID())
		}
		if signer.ThresholdIndex() != -1 {
			t.Fatalf("Expected index -1, got %d", signer.ThresholdIndex())
		}
		if signer.ThresholdPublicShare() != nil {
			t.Fatal("Expected nil public share")
		}
		if signer.ThresholdGroupKey() != nil {
			t.Fatal("Expected nil group key")
		}
		ctx := context.Background()
		if _, err := signer.SignThresholdShare(ctx, message, []int{0}); err != threshold.ErrNotInitialized {
			t.Fatalf("Expected ErrNotInitialized, got %v", err)
		}
		if _, err := signer.AggregateThresholdShares(ctx, message, nil); err != threshold.ErrNotInitialized {
			t.Fatalf("Expected ErrNotInitialized, got %v", err)
		}
		if err := signer.VerifyThresholdShare(message, nil, nil); err != threshold.ErrNotInitialized {
			t.Fatalf("Expected ErrNotInitialized, got %v", err)
		}
		if signer.VerifyThreshold(message, nil) {
			t.Fatal("Expected false without threshold key")
		}
		if signer.VerifyThresholdBytes(message, nil) {
			t.Fatal("Expected false without threshold key")
		}
	})
}

func BenchmarkSigner(b *testing.B) {
	signer, err := NewSigner()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Benchmark message for performance testing")

	b.Run("BLS_Sign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := signer.SignBLS(message); err != nil {
				b.Fatal(err)
			}
		}
	})

	blsSig, _ := signer.SignBLS(message)
	b.Run("BLS_Verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !signer.VerifyBLS(message, blsSig) {
				b.Fatal("Verification failed")
			}
		}
	})
}
