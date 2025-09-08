package unified

import (
	"testing"
)

func TestSimpleSigner(t *testing.T) {
	signer, err := NewSimpleSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	
	message := []byte("Test message for unified signing")
	
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
	
	t.Run("ML-DSA", func(t *testing.T) {
		sig, err := signer.SignMLDSA(message)
		if err != nil {
			t.Fatalf("ML-DSA sign failed: %v", err)
		}
		
		if !signer.VerifyMLDSA(message, sig) {
			t.Fatalf("ML-DSA verification failed")
		}
		
		if signer.VerifyMLDSA([]byte("wrong"), sig) {
			t.Fatalf("ML-DSA should not verify wrong message")
		}
		
		t.Logf("ML-DSA signature size: %d bytes", len(sig))
		t.Logf("ML-DSA public key size: %d bytes", len(signer.GetMLDSAPublicKey()))
	})
	
	t.Run("Hybrid", func(t *testing.T) {
		sig, err := signer.SignHybrid(message)
		if err != nil {
			t.Fatalf("Hybrid sign failed: %v", err)
		}
		
		if !signer.VerifyHybrid(message, sig) {
			t.Fatalf("Hybrid verification failed")
		}
		
		if signer.VerifyHybrid([]byte("wrong"), sig) {
			t.Fatalf("Hybrid should not verify wrong message")
		}
		
		t.Logf("Hybrid signature size: %d bytes", len(sig))
	})
}

func BenchmarkSimpleSigner(b *testing.B) {
	signer, err := NewSimpleSigner()
	if err != nil {
		b.Fatal(err)
	}
	
	message := []byte("Benchmark message for performance testing")
	
	b.Run("BLS_Sign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignBLS(message)
			if err != nil {
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
	
	b.Run("MLDSA_Sign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignMLDSA(message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	mldsaSig, _ := signer.SignMLDSA(message)
	b.Run("MLDSA_Verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !signer.VerifyMLDSA(message, mldsaSig) {
				b.Fatal("Verification failed")
			}
		}
	})
	
	b.Run("Hybrid_Sign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignHybrid(message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	hybridSig, _ := signer.SignHybrid(message)
	b.Run("Hybrid_Verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !signer.VerifyHybrid(message, hybridSig) {
				b.Fatal("Verification failed")
			}
		}
	})
}