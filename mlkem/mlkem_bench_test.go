package mlkem

import (
	"crypto/rand"
	"testing"
)

func BenchmarkMLKEM512(b *testing.B) {
	benchmarkMLKEM(b, MLKEM512)
}

func BenchmarkMLKEM768(b *testing.B) {
	benchmarkMLKEM(b, MLKEM768)
}

func BenchmarkMLKEM1024(b *testing.B) {
	benchmarkMLKEM(b, MLKEM1024)
}

func benchmarkMLKEM(b *testing.B, mode Mode) {
	b.Run("GenerateKeyPair", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, err := GenerateKeyPair(rand.Reader, mode)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	priv, _, err := GenerateKeyPair(rand.Reader, mode)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Encapsulate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := priv.PublicKey.Encapsulate(rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	result, err := priv.PublicKey.Encapsulate(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Decapsulate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := priv.Decapsulate(result.Ciphertext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Serialize", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = priv.Bytes()
			_ = priv.PublicKey.Bytes()
		}
	})

	privBytes := priv.Bytes()
	pubBytes := priv.PublicKey.Bytes()

	b.Run("Deserialize", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := PrivateKeyFromBytes(privBytes, mode)
			if err != nil {
				b.Fatal(err)
			}
			_, err = PublicKeyFromBytes(pubBytes, mode)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Memory usage benchmark
func BenchmarkMLKEMMemory(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"MLKEM512", MLKEM512},
		{"MLKEM768", MLKEM768},
		{"MLKEM1024", MLKEM1024},
	}

	for _, m := range modes {
		b.Run(m.name, func(b *testing.B) {
			b.ReportAllocs()
			priv, _, _ := GenerateKeyPair(rand.Reader, m.mode)
			result, _ := priv.PublicKey.Encapsulate(rand.Reader)
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Full KEM operation
				_, _ = priv.PublicKey.Encapsulate(rand.Reader)
				_, _ = priv.Decapsulate(result.Ciphertext)
			}
		})
	}
}