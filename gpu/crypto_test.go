//go:build cgo

package gpu

import (
	"bytes"
	"testing"
)

func TestGPUAvailable(t *testing.T) {
	available := GPUAvailable()
	backend := GetBackend()
	t.Logf("GPU Available: %v, Backend: %s", available, backend)
}

func TestBLSKeygen(t *testing.T) {
	sk, err := BLSKeygen(nil)
	if err != nil {
		t.Fatalf("BLSKeygen failed: %v", err)
	}
	if len(sk) != BLSSecretKeySize {
		t.Errorf("sk length = %d, want %d", len(sk), BLSSecretKeySize)
	}

	// Derive public key
	pk, err := BLSSecretKeyToPublicKey(sk)
	if err != nil {
		t.Fatalf("BLSSecretKeyToPublicKey failed: %v", err)
	}
	if len(pk) != BLSPublicKeySize {
		t.Errorf("pk length = %d, want %d", len(pk), BLSPublicKeySize)
	}

	t.Logf("Generated BLS keypair: sk=%d bytes, pk=%d bytes", len(sk), len(pk))
}

func TestBLSSignVerify(t *testing.T) {
	// Generate key
	sk, err := BLSKeygen(nil)
	if err != nil {
		t.Fatalf("BLSKeygen failed: %v", err)
	}

	pk, err := BLSSecretKeyToPublicKey(sk)
	if err != nil {
		t.Fatalf("BLSSecretKeyToPublicKey failed: %v", err)
	}

	// Sign message
	msg := make([]byte, BLSMessageSize)
	for i := range msg {
		msg[i] = byte(i)
	}

	sig, err := BLSSign(sk, msg)
	if err != nil {
		t.Fatalf("BLSSign failed: %v", err)
	}
	if len(sig) != BLSSignatureSize {
		t.Errorf("sig length = %d, want %d", len(sig), BLSSignatureSize)
	}

	// Verify signature
	valid := BLSVerify(sig, pk, msg)
	if !valid {
		t.Error("BLSVerify returned false for valid signature")
	}

	t.Log("BLS sign/verify successful")
}

func TestBLSAggregate(t *testing.T) {
	n := 5

	// Generate keys
	sks := make([][]byte, n)
	pks := make([][]byte, n)
	for i := 0; i < n; i++ {
		var err error
		sks[i], err = BLSKeygen(nil)
		if err != nil {
			t.Fatalf("BLSKeygen[%d] failed: %v", i, err)
		}
		pks[i], err = BLSSecretKeyToPublicKey(sks[i])
		if err != nil {
			t.Fatalf("BLSSecretKeyToPublicKey[%d] failed: %v", i, err)
		}
	}

	// Sign same message
	msg := make([]byte, BLSMessageSize)
	for i := range msg {
		msg[i] = byte(i * 2)
	}

	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		var err error
		sigs[i], err = BLSSign(sks[i], msg)
		if err != nil {
			t.Fatalf("BLSSign[%d] failed: %v", i, err)
		}
	}

	// Aggregate signatures
	aggSig, err := BLSAggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("BLSAggregateSignatures failed: %v", err)
	}

	// Aggregate public keys
	aggPK, err := BLSAggregatePublicKeys(pks)
	if err != nil {
		t.Fatalf("BLSAggregatePublicKeys failed: %v", err)
	}

	// Verify aggregated
	valid := BLSVerifyAggregated(aggSig, aggPK, msg)
	if !valid {
		t.Error("BLSVerifyAggregated returned false for valid aggregated signature")
	}

	t.Logf("BLS aggregate (%d signatures) successful", n)
}

func TestBLSBatchVerify(t *testing.T) {
	n := 10

	sigs := make([][]byte, n)
	pks := make([][]byte, n)
	msgs := make([][]byte, n)

	for i := 0; i < n; i++ {
		sk, err := BLSKeygen(nil)
		if err != nil {
			t.Fatalf("BLSKeygen[%d] failed: %v", i, err)
		}
		pks[i], err = BLSSecretKeyToPublicKey(sk)
		if err != nil {
			t.Fatalf("BLSSecretKeyToPublicKey[%d] failed: %v", i, err)
		}

		msgs[i] = make([]byte, BLSMessageSize)
		for j := range msgs[i] {
			msgs[i][j] = byte(i + j)
		}

		sigs[i], err = BLSSign(sk, msgs[i])
		if err != nil {
			t.Fatalf("BLSSign[%d] failed: %v", i, err)
		}
	}

	results, err := BLSBatchVerify(sigs, pks, msgs)
	if err != nil {
		t.Fatalf("BLSBatchVerify failed: %v", err)
	}

	if len(results) != n {
		t.Errorf("results length = %d, want %d", len(results), n)
	}

	validCount := 0
	for i, r := range results {
		if r {
			validCount++
		} else {
			t.Errorf("signature %d should be valid", i)
		}
	}

	t.Logf("BLS batch verify: %d/%d valid", validCount, n)
}

func TestMLDSAKeygen(t *testing.T) {
	pk, sk, err := MLDSAKeygen(nil)
	if err != nil {
		t.Fatalf("MLDSAKeygen failed: %v", err)
	}

	if len(pk) != MLDSAPublicKeySize {
		t.Errorf("pk length = %d, want %d", len(pk), MLDSAPublicKeySize)
	}
	if len(sk) != MLDSASecretKeySize {
		t.Errorf("sk length = %d, want %d", len(sk), MLDSASecretKeySize)
	}

	t.Logf("Generated ML-DSA keypair: pk=%d bytes, sk=%d bytes", len(pk), len(sk))
}

func TestMLDSASignVerify(t *testing.T) {
	pk, sk, err := MLDSAKeygen(nil)
	if err != nil {
		t.Fatalf("MLDSAKeygen failed: %v", err)
	}

	msg := []byte("Hello, ML-DSA post-quantum signatures!")

	sig, err := MLDSASign(sk, msg)
	if err != nil {
		t.Fatalf("MLDSASign failed: %v", err)
	}

	valid := MLDSAVerify(sig, msg, pk)
	if !valid {
		t.Error("MLDSAVerify returned false for valid signature")
	}

	t.Logf("ML-DSA sign/verify successful: sig=%d bytes", len(sig))
}

func TestThreshold(t *testing.T) {
	threshold := uint32(3)
	total := uint32(5)

	ctx, err := NewThresholdContext(threshold, total)
	if err != nil {
		t.Fatalf("NewThresholdContext failed: %v", err)
	}
	defer ctx.Close()

	// Generate shares
	shares, pk, err := ctx.Keygen(nil)
	if err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	if uint32(len(shares)) != total {
		t.Errorf("shares count = %d, want %d", len(shares), total)
	}
	if len(pk) != BLSPublicKeySize {
		t.Errorf("pk length = %d, want %d", len(pk), BLSPublicKeySize)
	}

	t.Logf("Generated %d shares, pk=%d bytes", len(shares), len(pk))

	// Create partial signatures
	msg := make([]byte, BLSMessageSize)
	for i := range msg {
		msg[i] = byte(i * 3)
	}

	partialSigs := make([][]byte, threshold)
	indices := make([]uint32, threshold)
	for i := uint32(0); i < threshold; i++ {
		var err error
		partialSigs[i], err = ctx.PartialSign(i, shares[i], msg)
		if err != nil {
			t.Fatalf("PartialSign[%d] failed: %v", i, err)
		}
		indices[i] = i
	}

	// Combine
	sig, err := ctx.Combine(partialSigs, indices)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	// Verify
	valid := ctx.Verify(sig, pk, msg)
	if !valid {
		t.Error("Verify returned false for valid threshold signature")
	}

	t.Logf("Threshold %d-of-%d signature successful", threshold, total)
}

func TestSHA3_256(t *testing.T) {
	data := []byte("test data for SHA3-256")
	hash := SHA3_256(data)

	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}

	// Same input should produce same output
	hash2 := SHA3_256(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("SHA3_256 is not deterministic")
	}

	t.Logf("SHA3-256: %x", hash)
}

func TestSHA3_512(t *testing.T) {
	data := []byte("test data for SHA3-512")
	hash := SHA3_512(data)

	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	t.Logf("SHA3-512: %x", hash)
}

func TestBLAKE3(t *testing.T) {
	data := []byte("test data for BLAKE3")
	hash := BLAKE3(data)

	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}

	t.Logf("BLAKE3: %x", hash)
}

func TestBatchHash(t *testing.T) {
	inputs := [][]byte{
		[]byte("input 1"),
		[]byte("input 2"),
		[]byte("input 3"),
		[]byte("input 4"),
	}

	// Test SHA3-256
	outputs, err := BatchHash(inputs, HashTypeSHA3_256)
	if err != nil {
		t.Fatalf("BatchHash(SHA3-256) failed: %v", err)
	}

	if len(outputs) != len(inputs) {
		t.Errorf("outputs count = %d, want %d", len(outputs), len(inputs))
	}

	for i, out := range outputs {
		if len(out) != 32 {
			t.Errorf("outputs[%d] length = %d, want 32", i, len(out))
		}
		// Verify against single hash
		expected := SHA3_256(inputs[i])
		if !bytes.Equal(out, expected) {
			t.Errorf("outputs[%d] mismatch: got %x, want %x", i, out, expected)
		}
	}

	t.Logf("BatchHash: %d hashes computed", len(outputs))
}

func TestConsensusVerifyBlock(t *testing.T) {
	n := 5

	// Generate validator keys
	sks := make([][]byte, n)
	pks := make([][]byte, n)
	for i := 0; i < n; i++ {
		var err error
		sks[i], err = BLSKeygen(nil)
		if err != nil {
			t.Fatalf("BLSKeygen[%d] failed: %v", i, err)
		}
		pks[i], err = BLSSecretKeyToPublicKey(sks[i])
		if err != nil {
			t.Fatalf("BLSSecretKeyToPublicKey[%d] failed: %v", i, err)
		}
	}

	// Block hash
	blockHash := make([]byte, BLSMessageSize)
	for i := range blockHash {
		blockHash[i] = byte(i)
	}

	// Sign with validators
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		var err error
		sigs[i], err = BLSSign(sks[i], blockHash)
		if err != nil {
			t.Fatalf("BLSSign[%d] failed: %v", i, err)
		}
	}

	// Verify block (without threshold sig)
	valid := ConsensusVerifyBlock(sigs, pks, nil, nil, blockHash)
	if !valid {
		t.Error("ConsensusVerifyBlock returned false for valid block")
	}

	t.Log("ConsensusVerifyBlock successful")
}

// Benchmarks

func BenchmarkBLSSign(b *testing.B) {
	sk, _ := BLSKeygen(nil)
	msg := make([]byte, BLSMessageSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BLSSign(sk, msg)
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	sk, _ := BLSKeygen(nil)
	pk, _ := BLSSecretKeyToPublicKey(sk)
	msg := make([]byte, BLSMessageSize)
	sig, _ := BLSSign(sk, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BLSVerify(sig, pk, msg)
	}
}

func BenchmarkBLSBatchVerify(b *testing.B) {
	n := 100
	sigs := make([][]byte, n)
	pks := make([][]byte, n)
	msgs := make([][]byte, n)

	for i := 0; i < n; i++ {
		sk, _ := BLSKeygen(nil)
		pks[i], _ = BLSSecretKeyToPublicKey(sk)
		msgs[i] = make([]byte, BLSMessageSize)
		sigs[i], _ = BLSSign(sk, msgs[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BLSBatchVerify(sigs, pks, msgs)
	}
}

func BenchmarkSHA3_256(b *testing.B) {
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA3_256(data)
	}
}

func BenchmarkBatchHash(b *testing.B) {
	n := 100
	inputs := make([][]byte, n)
	for i := 0; i < n; i++ {
		inputs[i] = make([]byte, 1024)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BatchHash(inputs, HashTypeSHA3_256)
	}
}
