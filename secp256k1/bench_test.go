// Benchmarks for secp256k1 that work with both CGO and non-CGO builds

package secp256k1

import (
	"crypto/rand"
	"testing"
)

func BenchmarkSignNoCGO(b *testing.B) {
	msg := make([]byte, 32)
	rand.Read(msg)
	
	seckey := make([]byte, 32)
	rand.Read(seckey)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(msg, seckey)
	}
}

func BenchmarkRecoverNoCGO(b *testing.B) {
	msg := make([]byte, 32)
	rand.Read(msg)
	
	seckey := make([]byte, 32)
	rand.Read(seckey)
	
	sig, _ := Sign(msg, seckey)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RecoverPubkey(msg, sig)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	msg := make([]byte, 32)
	rand.Read(msg)
	
	seckey := make([]byte, 32)
	rand.Read(seckey)
	
	sig, _ := Sign(msg, seckey)
	pubkey, _ := RecoverPubkey(msg, sig)
	
	// Remove recovery ID for verification
	sigNoRecovery := sig[:64]
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySignature(pubkey, msg, sigNoRecovery)
	}
}