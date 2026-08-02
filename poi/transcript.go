// Proof-of-Inference TRANSCRIPT (Go mirror of hanzo-engine/src/poi_transcript.rs).
//
// This is the wire that makes "no valid compute proof, no mint" real: a prover commits each
// proof-bearing matmul as a keccak Merkle leaf over its exact-integer (A,B,C); the Merkle root is
// the transcriptRoot posted on-chain. The off-chain watcher (and the computeattest precompile)
// challenge a beacon-selected matmul, the prover OPENS it, and VerifyOpening (1) checks the
// operands were the committed ones (Merkle inclusion, the same index-fold as
// AICoinMiner._verifyMerkle) and (2) Freivalds-verifies C = A·B (Verify, this package). A
// fabricated output fails (2); a swapped-in output fails (1). This file is what gives the Verify
// primitive a production caller — the watcher imports it and slashes a bond on a failed opening.
//
// Byte-for-byte identical to the Rust prover: same DOMAIN tag, same canonical Mat serialization,
// same keccak fold, same DeriveChallenges. An opening produced by the engine verifies here and
// on-chain without re-hashing.
package poi

import (
	"encoding/binary"

	"github.com/luxfi/crypto"
)

// DomainMatmulLeaf tags a matmul leaf, disjoint from any other keccak leaf in the bridge.
var DomainMatmulLeaf = []byte("hanzo/poi/matmul-leaf/v1")

// ExactMatmul is the whole-K i64 exact-integer product C = A·B — the proof-bearing GEMM whose
// output Freivalds checks with zero false-reject (mirrors poi::exact_matmul).
func ExactMatmul(a, b Mat) Mat {
	if a.Cols != b.Rows {
		panic("poi: ExactMatmul dim mismatch a.Cols != b.Rows")
	}
	t, k, n := a.Rows, a.Cols, b.Cols
	c := make([]int64, t*n)
	for i := 0; i < t; i++ {
		for j := 0; j < n; j++ {
			var acc int64
			for x := 0; x < k; x++ {
				acc += a.Data[i*k+x] * b.Data[x*n+j]
			}
			c[i*n+j] = acc
		}
	}
	return NewMat(t, n, c)
}

// matBytes is the canonical serialization: BE32(rows) ‖ BE32(cols) ‖ data[i] as BE64.
func matBytes(m Mat) []byte {
	b := make([]byte, 0, 8+len(m.Data)*8)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(m.Rows))
	b = append(b, u32[:]...)
	binary.BigEndian.PutUint32(u32[:], uint32(m.Cols))
	b = append(b, u32[:]...)
	var u64 [8]byte
	for _, x := range m.Data {
		binary.BigEndian.PutUint64(u64[:], uint64(x))
		b = append(b, u64[:]...)
	}
	return b
}

// MatmulLeaf binds one matmul: keccak(DOMAIN ‖ mat(A) ‖ mat(B) ‖ mat(C)).
func MatmulLeaf(a, b, c Mat) [32]byte {
	buf := make([]byte, 0, len(DomainMatmulLeaf)+8)
	buf = append(buf, DomainMatmulLeaf...)
	buf = append(buf, matBytes(a)...)
	buf = append(buf, matBytes(b)...)
	buf = append(buf, matBytes(c)...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out
}

func hashPair(l, r [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], l[:])
	copy(buf[32:], r[:])
	var out [32]byte
	copy(out[:], crypto.Keccak256(buf[:]))
	return out
}

// MerkleRoot folds leaves into a keccak root; odd levels duplicate the last node; the index fold
// matches AICoinMiner._verifyMerkle (even → keccak(node‖sib), odd → keccak(sib‖node)).
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		panic("poi: MerkleRoot over empty transcript")
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][32]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// MerkleProof returns the bottom-up sibling path for the leaf at index.
func MerkleProof(leaves [][32]byte, index int) [][32]byte {
	var proof [][32]byte
	level := append([][32]byte(nil), leaves...)
	idx := index
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		var sib int
		if idx%2 == 0 {
			sib = idx + 1
		} else {
			sib = idx - 1
		}
		proof = append(proof, level[sib])
		next := make([][32]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
		idx /= 2
	}
	return proof
}

// MerkleVerify checks a leaf's inclusion under root at index — the exact fold of _verifyMerkle.
func MerkleVerify(leaf, root [32]byte, index int, proof [][32]byte) bool {
	node := leaf
	idx := index
	for _, sib := range proof {
		if idx%2 == 0 {
			node = hashPair(node, sib)
		} else {
			node = hashPair(sib, node)
		}
		idx /= 2
	}
	return node == root
}

// Opening is what a prover reveals to answer a challenge.
type Opening struct {
	Index   int
	A, B, C Mat
	Proof   [][32]byte
}

// ProofTranscript is an append-only commitment to a forward pass's proof-bearing matmuls.
type ProofTranscript struct {
	leaves [][32]byte
	ops    [][3]Mat
}

func NewTranscript() *ProofTranscript { return &ProofTranscript{} }

// Matmul runs an exact-integer matmul, commits it, and returns C.
func (t *ProofTranscript) Matmul(a, b Mat) Mat {
	c := ExactMatmul(a, b)
	t.leaves = append(t.leaves, MatmulLeaf(a, b, c))
	t.ops = append(t.ops, [3]Mat{a, b, c})
	return c
}

// CommitClaimed commits a matmul whose C is supplied by the caller (a claimed fast-path output).
func (t *ProofTranscript) CommitClaimed(a, b, c Mat) {
	t.leaves = append(t.leaves, MatmulLeaf(a, b, c))
	t.ops = append(t.ops, [3]Mat{a, b, c})
}

func (t *ProofTranscript) Len() int { return len(t.leaves) }

// Root is the transcriptRoot the prover posts on-chain.
func (t *ProofTranscript) Root() [32]byte { return MerkleRoot(t.leaves) }

// Open reveals the matmul at index with its inclusion proof.
func (t *ProofTranscript) Open(index int) Opening {
	o := t.ops[index]
	return Opening{Index: index, A: o[0], B: o[1], C: o[2], Proof: MerkleProof(t.leaves, index)}
}

// ChallengeIndex selects which matmul to open: keccak(beacon ‖ root) mod len. Unpredictable
// before the prover commits root.
func ChallengeIndex(beacon []byte, root [32]byte, length int) int {
	buf := append(append([]byte(nil), beacon...), root[:]...)
	h := crypto.Keccak256(buf)
	return int(binary.BigEndian.Uint64(h[:8]) % uint64(length))
}

// OpeningSeed binds the Freivalds challenge to (beacon, root, index): keccak(beacon ‖ root ‖ BE64(index)).
func OpeningSeed(beacon []byte, root [32]byte, index int) []byte {
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], uint64(index))
	buf := append(append(append([]byte(nil), beacon...), root[:]...), u64[:]...)
	return crypto.Keccak256(buf)
}

// VerifyOpening is THE CHALLENGER: (1) the revealed operands are the committed ones (Merkle
// inclusion under root), and (2) C = A·B (Freivalds, k beacon-bound vectors). True iff both.
// This is the production caller of Verify — the watcher slashes a bond when this returns false.
func VerifyOpening(root [32]byte, beacon []byte, op Opening, k int) bool {
	leaf := MatmulLeaf(op.A, op.B, op.C)
	if !MerkleVerify(leaf, root, op.Index, op.Proof) {
		return false
	}
	seed := OpeningSeed(beacon, root, op.Index)
	challenges := DeriveChallenges(seed, op.B.Cols, k)
	return VerifyMulti(op.A, op.B, op.C, challenges)
}
