package gpu

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// TestFr256Conversion tests Fr256 <-> gnark-crypto conversion.
func TestFr256Conversion(t *testing.T) {
	// Create a random field element
	var e fr.Element
	e.SetRandom()

	// Convert to Fr256
	var f Fr256
	f.FromGnark(&e)

	// Convert back
	e2 := f.ToGnark()

	// Should be equal
	if !e.Equal(&e2) {
		t.Errorf("Conversion roundtrip failed: got %v, want %v", e2, e)
	}
}

// TestFr256Bytes tests Fr256 byte serialization.
func TestFr256Bytes(t *testing.T) {
	var f Fr256
	f[0] = 0x1234567890abcdef
	f[1] = 0xfedcba0987654321
	f[2] = 0xabcdef0123456789
	f[3] = 0x9876543210fedcba

	// Serialize
	buf := f.Bytes()
	if len(buf) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(buf))
	}

	// Deserialize
	var f2 Fr256
	if err := f2.SetBytes(buf); err != nil {
		t.Fatalf("SetBytes failed: %v", err)
	}

	// Should be equal
	if f != f2 {
		t.Errorf("Byte roundtrip failed: got %v, want %v", f2, f)
	}
}

// TestPoseidon2HashPair tests single Poseidon2 hash.
func TestPoseidon2HashPair(t *testing.T) {
	ctx := GetZKContext()

	// Create test inputs
	var left, right Fr256
	left[0] = 1
	right[0] = 2

	// Compute hash
	result := ctx.Poseidon2HashPair(&left, &right)

	// Result should be non-zero
	if result == (Fr256{}) {
		t.Error("Poseidon2 hash returned zero")
	}

	// Same inputs should give same output (deterministic)
	result2 := ctx.Poseidon2HashPair(&left, &right)
	if result != result2 {
		t.Error("Poseidon2 hash not deterministic")
	}

	// Different inputs should give different output
	left[0] = 3
	result3 := ctx.Poseidon2HashPair(&left, &right)
	if result == result3 {
		t.Error("Different inputs gave same hash")
	}
}

// TestPoseidon2BatchHashPair tests batch Poseidon2 hashing.
func TestPoseidon2BatchHashPair(t *testing.T) {
	ctx := GetZKContext()

	n := 16
	left := make([]Fr256, n)
	right := make([]Fr256, n)

	for i := 0; i < n; i++ {
		left[i][0] = uint64(i)
		right[i][0] = uint64(i + n)
	}

	// Compute batch hash
	results, err := ctx.Poseidon2BatchHashPair(left, right)
	if err != nil {
		t.Fatalf("BatchHashPair failed: %v", err)
	}

	if len(results) != n {
		t.Fatalf("Expected %d results, got %d", n, len(results))
	}

	// Verify each result matches individual hash
	for i := 0; i < n; i++ {
		expected := ctx.Poseidon2HashPair(&left[i], &right[i])
		if results[i] != expected {
			t.Errorf("Result[%d] mismatch: got %v, want %v", i, results[i], expected)
		}
	}
}

// TestPoseidon2MerkleRoot tests Merkle root computation.
func TestPoseidon2MerkleRoot(t *testing.T) {
	ctx := GetZKContext()

	// Test with 4 leaves
	leaves := make([]Fr256, 4)
	for i := 0; i < 4; i++ {
		leaves[i][0] = uint64(i + 1)
	}

	root, err := ctx.Poseidon2MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("MerkleRoot failed: %v", err)
	}

	// Root should be non-zero
	if root == (Fr256{}) {
		t.Error("Merkle root is zero")
	}

	// Compute manually to verify
	// Level 1: hash(L0, L1), hash(L2, L3)
	h01 := ctx.Poseidon2HashPair(&leaves[0], &leaves[1])
	h23 := ctx.Poseidon2HashPair(&leaves[2], &leaves[3])
	// Level 0 (root): hash(h01, h23)
	expectedRoot := ctx.Poseidon2HashPair(&h01, &h23)

	if root != expectedRoot {
		t.Errorf("Merkle root mismatch: got %v, want %v", root, expectedRoot)
	}
}

// TestPoseidon2MerkleTree tests complete Merkle tree building.
func TestPoseidon2MerkleTree(t *testing.T) {
	ctx := GetZKContext()

	// Test with 8 leaves
	leaves := make([]Fr256, 8)
	for i := 0; i < 8; i++ {
		leaves[i][0] = uint64(i + 1)
	}

	tree, err := ctx.Poseidon2MerkleTree(leaves)
	if err != nil {
		t.Fatalf("MerkleTree failed: %v", err)
	}

	// Should have 7 internal nodes (n-1 for n=8)
	expectedNodes := 7
	if len(tree) != expectedNodes {
		t.Fatalf("Expected %d nodes, got %d", expectedNodes, len(tree))
	}

	// Last node should be the root
	root, err := ctx.Poseidon2MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("MerkleRoot failed: %v", err)
	}

	if tree[len(tree)-1] != root {
		t.Error("Last tree node should be root")
	}
}

// TestPoseidon2Commitment tests commitment computation.
func TestPoseidon2Commitment(t *testing.T) {
	ctx := GetZKContext()

	var value, blinding, salt Fr256
	value[0] = 100
	blinding[0] = 0xdeadbeef
	salt[0] = 0xcafebabe

	commitment := ctx.Poseidon2Commitment(&value, &blinding, &salt)

	// Should be non-zero
	if commitment == (Fr256{}) {
		t.Error("Commitment is zero")
	}

	// Same inputs should give same commitment
	commitment2 := ctx.Poseidon2Commitment(&value, &blinding, &salt)
	if commitment != commitment2 {
		t.Error("Commitment not deterministic")
	}

	// Different blinding should give different commitment
	blinding[0] = 0xfeedface
	commitment3 := ctx.Poseidon2Commitment(&value, &blinding, &salt)
	if commitment == commitment3 {
		t.Error("Different blinding gave same commitment")
	}
}

// TestPoseidon2Nullifier tests nullifier computation.
func TestPoseidon2Nullifier(t *testing.T) {
	ctx := GetZKContext()

	var key, commitment, index Fr256
	key[0] = 0x1234
	commitment[0] = 0x5678
	index[0] = 42

	nullifier := ctx.Poseidon2Nullifier(&key, &commitment, &index)

	// Should be non-zero
	if nullifier == (Fr256{}) {
		t.Error("Nullifier is zero")
	}

	// Same inputs should give same nullifier
	nullifier2 := ctx.Poseidon2Nullifier(&key, &commitment, &index)
	if nullifier != nullifier2 {
		t.Error("Nullifier not deterministic")
	}
}

// TestBatchCommitment tests batch commitment computation.
func TestBatchCommitment(t *testing.T) {
	ctx := GetZKContext()

	n := 10
	values := make([]Fr256, n)
	blindings := make([]Fr256, n)
	salts := make([]Fr256, n)

	for i := 0; i < n; i++ {
		values[i][0] = uint64(i * 100)
		blindings[i][0] = uint64(i * 1000 + 1)
		salts[i][0] = uint64(i * 10000 + 2)
	}

	commitments, err := ctx.BatchCommitment(values, blindings, salts)
	if err != nil {
		t.Fatalf("BatchCommitment failed: %v", err)
	}

	if len(commitments) != n {
		t.Fatalf("Expected %d commitments, got %d", n, len(commitments))
	}

	// Verify each commitment matches individual computation
	for i := 0; i < n; i++ {
		expected := ctx.Poseidon2Commitment(&values[i], &blindings[i], &salts[i])
		if commitments[i] != expected {
			t.Errorf("Commitment[%d] mismatch", i)
		}
	}
}

// TestZKContextStats tests statistics tracking.
func TestZKContextStats(t *testing.T) {
	ctx := GetZKContext()

	// Get initial stats
	gpuBefore, cpuBefore := ctx.Stats()

	// Do some operations
	var left, right Fr256
	left[0] = 1
	right[0] = 2
	_ = ctx.Poseidon2HashPair(&left, &right)
	_ = ctx.Poseidon2HashPair(&left, &right)

	// Check stats increased
	gpuAfter, cpuAfter := ctx.Stats()

	// CPU calls should have increased (single hashes always use CPU)
	if cpuAfter <= cpuBefore {
		t.Error("CPU calls did not increase")
	}

	t.Logf("Stats: GPU=%d (delta=%d), CPU=%d (delta=%d)",
		gpuAfter, gpuAfter-gpuBefore, cpuAfter, cpuAfter-cpuBefore)
}

// TestThresholdConstants tests threshold constant values.
func TestThresholdConstants(t *testing.T) {
	// Verify thresholds are reasonable
	if ThresholdPoseidon2 < 1 {
		t.Error("ThresholdPoseidon2 should be >= 1")
	}
	if ThresholdMerkle < 1 {
		t.Error("ThresholdMerkle should be >= 1")
	}
	if ThresholdMSM < 1 {
		t.Error("ThresholdMSM should be >= 1")
	}
	if ThresholdCommitment < 1 {
		t.Error("ThresholdCommitment should be >= 1")
	}
	if ThresholdFRI < 1 {
		t.Error("ThresholdFRI should be >= 1")
	}

	t.Logf("Thresholds: Poseidon2=%d, Merkle=%d, MSM=%d, Commitment=%d, FRI=%d",
		ThresholdPoseidon2, ThresholdMerkle, ThresholdMSM, ThresholdCommitment, ThresholdFRI)
}

// TestConvenienceFunctions tests the package-level convenience functions.
func TestConvenienceFunctions(t *testing.T) {
	var left, right Fr256
	left[0] = 10
	right[0] = 20

	// Test Poseidon2Hash
	hash := Poseidon2Hash(&left, &right)
	if hash == (Fr256{}) {
		t.Error("Poseidon2Hash returned zero")
	}

	// Test MerkleRoot
	leaves := []Fr256{left, right, left, right}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("MerkleRoot failed: %v", err)
	}
	if root == (Fr256{}) {
		t.Error("MerkleRoot returned zero")
	}

	// Test Commitment
	var salt Fr256
	salt[0] = 30
	commitment := Commitment(&left, &right, &salt)
	if commitment == (Fr256{}) {
		t.Error("Commitment returned zero")
	}

	// Test Nullifier
	nullifier := Nullifier(&left, &right, &salt)
	if nullifier == (Fr256{}) {
		t.Error("Nullifier returned zero")
	}
}

// BenchmarkPoseidon2HashPair benchmarks single Poseidon2 hash.
func BenchmarkPoseidon2HashPair(b *testing.B) {
	ctx := GetZKContext()
	var left, right Fr256
	left[0] = 1
	right[0] = 2

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.Poseidon2HashPair(&left, &right)
	}
}

// BenchmarkPoseidon2BatchHash benchmarks batch Poseidon2 hashing.
func BenchmarkPoseidon2BatchHash(b *testing.B) {
	ctx := GetZKContext()
	sizes := []int{16, 64, 256, 1024}

	for _, size := range sizes {
		left := make([]Fr256, size)
		right := make([]Fr256, size)
		for i := 0; i < size; i++ {
			left[i][0] = uint64(i)
			right[i][0] = uint64(i + size)
		}

		b.Run(
			func(n int) string {
				if n >= ThresholdPoseidon2 {
					return "GPU"
				}
				return "CPU"
			}(size)+"-"+string(rune('0'+size/100)),
			func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = ctx.Poseidon2BatchHashPair(left, right)
				}
			})
	}
}

// BenchmarkMerkleRoot benchmarks Merkle root computation.
func BenchmarkMerkleRoot(b *testing.B) {
	ctx := GetZKContext()
	sizes := []int{8, 64, 256, 1024}

	for _, size := range sizes {
		leaves := make([]Fr256, size)
		for i := 0; i < size; i++ {
			leaves[i][0] = uint64(i + 1)
		}

		b.Run(
			func(n int) string {
				if n >= ThresholdMerkle*2 {
					return "GPU"
				}
				return "CPU"
			}(size)+"-"+string(rune('0'+size/100)),
			func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = ctx.Poseidon2MerkleRoot(leaves)
				}
			})
	}
}
