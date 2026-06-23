// Package poi is the canonical Proof-of-Inference verifier primitive.
//
// Proof-of-AI binds reward to genuine computation: an LLM forward pass is ~95% matrix
// multiplications C = A·B, and Freivalds (1977) verifies one for a random vector r via
// A·(B·r) == C·r in O(t·k + k·n + t·n) — an order cheaper than recomputing — catching a
// fabricated C (a claimed output the prover never multiplied for) with probability >= 1 - 1/p
// per vector. We work over the prime field F_p, p = 2^61-1, on the EXACT INTEGER accumulator
// of the engine's int8 matmul (i8·i8 -> i32), so the check is bit-exact with ZERO false-reject
// across CPU/GPU/backends — the determinism the whole scheme relies on. Soundness error is
// 1/p ~ 2^-61 per challenge vector; k=2 vectors give <= 2^-122.
//
// This is the CANONICAL verifier the chain consumes (chains/aivm settlement, the aivmbridge /
// computeattest precompile). It sits beside crypto.Keccak256 so a future compute_proof.go and
// the on-chain transcript verification share one hash and one field. The engine's Rust
// hanzo-engine/src/poi.rs is the PROVER-side mirror and must match this byte-for-byte (same
// pattern as the receipt wire spec mirrored Go aivmbridge <-> Solidity AICoinMiner); a luxcpp
// C++ mirror provides a native/precompile-speed verifier.
package poi

import (
	"encoding/binary"
	"math/bits"

	"github.com/luxfi/crypto"
)

// P is the Mersenne prime field modulus p = 2^61 - 1. It bounds the int8 accumulator and the
// Freivalds intermediates within 61 bits, so a single 128-bit multiply never overflows.
const P uint64 = (1 << 61) - 1

// Mat is a dense row-major integer matrix (the int8 path's exact i32/i64 accumulators).
type Mat struct {
	Rows int
	Cols int
	Data []int64 // element (i,j) = Data[i*Cols+j]
}

// NewMat builds a matrix, panicking on a length mismatch (programmer error).
func NewMat(rows, cols int, data []int64) Mat {
	if len(data) != rows*cols {
		panic("poi: Mat data length must be rows*cols")
	}
	return Mat{Rows: rows, Cols: cols, Data: data}
}

func (m Mat) at(i, j int) int64 { return m.Data[i*m.Cols+j] }

// toField reduces a signed integer into [0, p). Handles negative int8 weights/activations.
func toField(x int64) uint64 {
	r := x % int64(P)
	if r < 0 {
		r += int64(P)
	}
	return uint64(r)
}

// fadd returns (a + b) mod p for a, b < p (sum < 2p < 2^62, no overflow).
func fadd(a, b uint64) uint64 {
	s := a + b
	if s >= P {
		return s - P
	}
	return s
}

// fmul returns (a * b) mod p via a 128-bit multiply (both < p < 2^61, so the high word < p
// and bits.Div64 is well-defined).
func fmul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, P)
	return rem
}

// matvec computes m·v over F_p: m is an INTEGER matrix (reduced per entry), v a field vector of
// length m.Cols. Returns a field vector of length m.Rows.
func matvec(m Mat, v []uint64) []uint64 {
	out := make([]uint64, m.Rows)
	for i := 0; i < m.Rows; i++ {
		var acc uint64
		for j := 0; j < m.Cols; j++ {
			acc = fadd(acc, fmul(toField(m.at(i, j)), v[j]))
		}
		out[i] = acc
	}
	return out
}

// Verify checks C == A·B probabilistically for ONE challenge vector r (length n).
// Dims: A is [t x k], B is [k x n], C is [t x n], r is length n. O(tk + kn + tn).
func Verify(a, b, c Mat, r []uint64) bool {
	if a.Cols != b.Rows || b.Cols != c.Cols || a.Rows != c.Rows || len(r) != b.Cols {
		return false
	}
	br := matvec(b, r)   // length k
	abr := matvec(a, br) // length t
	cr := matvec(c, r)   // length t
	return equalU64(abr, cr)
}

// VerifyMulti checks against k independent challenge vectors. Honest C passes ALL; a tampered C
// fails at least one except with probability <= (1/p)^k. Returns true iff every vector passes.
func VerifyMulti(a, b, c Mat, challenges [][]uint64) bool {
	if len(challenges) == 0 {
		return false
	}
	for _, r := range challenges {
		if !Verify(a, b, c, r) {
			return false
		}
	}
	return true
}

// DeriveChallenges derives k challenge vectors of length n over F_p from a seed, using the
// canonical keccak the rest of the bridge uses. Reproducible by prover and verifier; in
// production the seed is keccak(beacon || task || transcriptRoot) so it is unpredictable before
// the prover commits.
func DeriveChallenges(seed []byte, n, k int) [][]uint64 {
	out := make([][]uint64, k)
	for j := 0; j < k; j++ {
		row := make([]uint64, n)
		for i := 0; i < n; i++ {
			var idx [12]byte
			binary.BigEndian.PutUint32(idx[0:4], uint32(j))
			binary.BigEndian.PutUint64(idx[4:12], uint64(i))
			h := crypto.Keccak256(seed, idx[:])
			row[i] = binary.BigEndian.Uint64(h[:8]) % P
		}
		out[j] = row
	}
	return out
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
