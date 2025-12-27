//go:build !cgo

package gpu

import (
	"bytes"
	"testing"
)

func TestNoCGO_GPUAvailable(t *testing.T) {
	if GPUAvailable() {
		t.Error("GPUAvailable should return false without CGO")
	}

	backend := GetBackend()
	if backend != "CPU (pure Go)" {
		t.Errorf("GetBackend = %q, want %q", backend, "CPU (pure Go)")
	}

	t.Logf("Backend: %s (pure Go fallback active)", backend)
}

func TestNoCGO_BLSFunctions(t *testing.T) {
	// Test BLSKeygen with seed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	sk, err := BLSKeygen(seed)
	if err != nil {
		t.Fatalf("BLSKeygen with seed failed: %v", err)
	}
	if len(sk) == 0 {
		t.Fatal("BLSKeygen returned empty secret key")
	}
	t.Logf("BLS secret key generated: %d bytes", len(sk))

	// Test BLSKeygen without seed (random)
	sk2, err := BLSKeygen(nil)
	if err != nil {
		t.Fatalf("BLSKeygen without seed failed: %v", err)
	}
	if bytes.Equal(sk, sk2) {
		t.Error("Two BLSKeygen calls should produce different keys")
	}

	// Test BLSSecretKeyToPublicKey
	pk, err := BLSSecretKeyToPublicKey(sk)
	if err != nil {
		t.Fatalf("BLSSecretKeyToPublicKey failed: %v", err)
	}
	if len(pk) == 0 {
		t.Fatal("BLSSecretKeyToPublicKey returned empty public key")
	}
	t.Logf("BLS public key derived: %d bytes", len(pk))

	// Test BLSSign
	message := SHA3_256([]byte("test message for BLS signature")) // 32 bytes
	sig, err := BLSSign(sk, message)
	if err != nil {
		t.Fatalf("BLSSign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("BLSSign returned empty signature")
	}
	t.Logf("BLS signature generated: %d bytes", len(sig))

	// Test BLSVerify - signature order is (sig, pk, msg)
	valid := BLSVerify(sig, pk, message)
	if !valid {
		t.Error("BLSVerify failed for valid signature")
	}

	// Test verification with wrong message
	wrongMessage := SHA3_256([]byte("wrong message"))
	if BLSVerify(sig, pk, wrongMessage) {
		t.Error("BLSVerify should fail for wrong message")
	}

	t.Log("All BLS functions work correctly in pure Go mode")
}

func TestNoCGO_MLDSAFunctions(t *testing.T) {
	// Test MLDSAKeygen with seed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	pk, sk, err := MLDSAKeygen(seed)
	if err != nil {
		t.Fatalf("MLDSAKeygen with seed failed: %v", err)
	}
	if len(pk) == 0 {
		t.Fatal("MLDSAKeygen returned empty public key")
	}
	if len(sk) == 0 {
		t.Fatal("MLDSAKeygen returned empty secret key")
	}
	t.Logf("ML-DSA keypair generated: pk=%d bytes, sk=%d bytes", len(pk), len(sk))

	// Test MLDSAKeygen without seed (random)
	pk2, sk2, err := MLDSAKeygen(nil)
	if err != nil {
		t.Fatalf("MLDSAKeygen without seed failed: %v", err)
	}
	if bytes.Equal(pk, pk2) || bytes.Equal(sk, sk2) {
		t.Error("Two MLDSAKeygen calls should produce different keypairs")
	}

	// Test MLDSASign
	message := []byte("test message for ML-DSA signature")
	sig, err := MLDSASign(sk, message)
	if err != nil {
		t.Fatalf("MLDSASign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("MLDSASign returned empty signature")
	}
	t.Logf("ML-DSA signature generated: %d bytes", len(sig))

	// Test MLDSAVerify - argument order is (sig, msg, pk)
	valid := MLDSAVerify(sig, message, pk)
	if !valid {
		t.Error("MLDSAVerify failed for valid signature")
	}

	// Test verification with wrong message
	wrongMessage := []byte("wrong message")
	if MLDSAVerify(sig, wrongMessage, pk) {
		t.Error("MLDSAVerify should fail for wrong message")
	}

	t.Log("All ML-DSA functions work correctly in pure Go mode")
}

func TestNoCGO_HashFunctions(t *testing.T) {
	data := []byte("test data for hashing")

	// Test SHA3_256
	hash := SHA3_256(data)
	if len(hash) != 32 {
		t.Errorf("SHA3_256 output length = %d, want 32", len(hash))
	}
	t.Logf("SHA3-256: %x", hash)

	// Test SHA3_512
	hash = SHA3_512(data)
	if len(hash) != 64 {
		t.Errorf("SHA3_512 output length = %d, want 64", len(hash))
	}
	t.Logf("SHA3-512: %x", hash[:32])

	// Test BLAKE3
	hash = BLAKE3(data)
	if len(hash) != 32 {
		t.Errorf("BLAKE3 output length = %d, want 32", len(hash))
	}
	t.Logf("BLAKE3: %x", hash)

	// Test BatchHash
	inputs := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
	}
	hashes, err := BatchHash(inputs, HashTypeSHA3_256)
	if err != nil {
		t.Fatalf("BatchHash failed: %v", err)
	}
	if len(hashes) != len(inputs) {
		t.Errorf("BatchHash returned %d hashes, want %d", len(hashes), len(inputs))
	}

	t.Log("All hash functions work correctly in pure Go mode")
}

func TestNoCGO_ThresholdContext(t *testing.T) {
	// Test creating threshold context
	ctx, err := NewThresholdContext(2, 3) // 2-of-3
	if err != nil {
		t.Fatalf("NewThresholdContext failed: %v", err)
	}
	defer ctx.Close()

	t.Logf("Threshold context created: t=%d, n=%d", ctx.t, ctx.n)

	// Test keygen - returns (shares, pk, err)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 42)
	}
	shares, pk, err := ctx.Keygen(seed)
	if err != nil {
		t.Fatalf("Threshold Keygen failed: %v", err)
	}
	if len(pk) == 0 {
		t.Fatal("Keygen returned empty public key")
	}
	if len(shares) != 3 {
		t.Errorf("Keygen returned %d shares, want 3", len(shares))
	}
	t.Logf("Threshold keygen complete: pk=%d bytes, %d shares", len(pk), len(shares))

	// Test signing
	message := SHA3_256([]byte("threshold test message")) // 32 bytes for BLS
	partialSigs := make([][]byte, 2)
	indices := []uint32{0, 2} // Use first and third party

	for i, idx := range indices {
		ps, err := ctx.PartialSign(idx, shares[idx], message)
		if err != nil {
			t.Fatalf("Threshold PartialSign for party %d failed: %v", idx, err)
		}
		partialSigs[i] = ps
	}
	t.Logf("Generated %d partial signatures", len(partialSigs))

	// Test combination
	sig, err := ctx.Combine(partialSigs, indices)
	if err != nil {
		t.Fatalf("Threshold Combine failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Combine returned empty signature")
	}
	t.Logf("Combined signature: %d bytes", len(sig))

	// Test verification - Verify(sig, pk, msg)
	valid := ctx.Verify(sig, pk, message)
	if !valid {
		t.Error("Threshold Verify failed for valid signature")
	}

	// Test verification with wrong message
	wrongMessage := SHA3_256([]byte("wrong message"))
	if ctx.Verify(sig, pk, wrongMessage) {
		t.Error("Threshold Verify should fail for wrong message")
	}

	t.Log("All threshold functions work correctly in pure Go mode")
}

func TestNoCGO_ConsensusVerifyBlock(t *testing.T) {
	// Create test data - need arrays of signatures and public keys
	blockHash := SHA3_256([]byte("test block"))

	// Generate BLS keypairs
	sk1, _ := BLSKeygen(nil)
	pk1, _ := BLSSecretKeyToPublicKey(sk1)
	sig1, _ := BLSSign(sk1, blockHash)

	sk2, _ := BLSKeygen(nil)
	pk2, _ := BLSSecretKeyToPublicKey(sk2)
	sig2, _ := BLSSign(sk2, blockHash)

	blsSigs := [][]byte{sig1, sig2}
	blsPKs := [][]byte{pk1, pk2}

	// Test consensus verify with multiple BLS signatures
	result := ConsensusVerifyBlock(blsSigs, blsPKs, nil, nil, blockHash)
	if !result {
		t.Error("ConsensusVerifyBlock failed for valid signatures")
	}
	t.Logf("ConsensusVerifyBlock with %d BLS signatures: %v", len(blsSigs), result)

	// Test with threshold signature too
	ctx, _ := NewThresholdContext(2, 3)
	defer ctx.Close()

	shares, threshPK, _ := ctx.Keygen(nil)
	ps1, _ := ctx.PartialSign(0, shares[0], blockHash)
	ps2, _ := ctx.PartialSign(1, shares[1], blockHash)
	threshSig, _ := ctx.Combine([][]byte{ps1, ps2}, []uint32{0, 1})

	result = ConsensusVerifyBlock(blsSigs, blsPKs, threshSig, threshPK, blockHash)
	if !result {
		t.Error("ConsensusVerifyBlock failed with threshold signature")
	}
	t.Logf("ConsensusVerifyBlock with BLS + threshold: %v", result)

	t.Log("ConsensusVerifyBlock works correctly in pure Go mode")
}
