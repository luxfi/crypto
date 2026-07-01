# `poi` — Proof-of-Inference verifier primitive

Freivalds-over-`F_p` matrix-product verification, plus a Merkle transcript and
wire codec for on-chain openings. This is the canonical Go verifier that
`luxfi/precompile/aivmbridge/computeproof.go` consumes and that
`hanzo-engine/src/poi.rs` mirrors on the prover side.

See **LP-5300** (Thinking Chains / Proof-of-Thought) for the receipt model this
serves, and **LP-5301** (AIVMBridge) for the precompile that calls this code
in-EVM.

## Overview

Proof-of-AI binds mint to genuine computation. An LLM forward pass is ~95%
matrix multiplications `C = A·B`. Recomputing every `C` on-chain is
prohibitive; Freivalds (1977) instead samples a random vector `r` and checks

    A·(B·r) == C·r

in `O(t·k + k·n + t·n)` — an order cheaper than the `O(t·k·n)` recompute — and
catches any fabricated `C` (a claimed output the prover never multiplied for)
with probability `>= 1 - 1/p` per vector.

The verifier operates on the **exact-integer** accumulator of the engine's
int8 matmul path (`i8·i8 -> i32` promoted to `int64`). Working on the exact
accumulator, not on floats, means the check is bit-exact with **zero
false-reject across CPU / GPU / backends** — the determinism the whole scheme
relies on.

## Mathematical setup

- Field: `F_p` with prime modulus `P = 2^61 - 1` (a Mersenne prime; see
  `freivalds.go` — `const P uint64 = (1 << 61) - 1`).
- Signed inputs are reduced into `[0, p)` by `toField`; a single Freivalds
  intermediate stays within 61 bits, so a 128-bit multiply never overflows.
- Soundness: `1/p ~ 2^-61` per challenge vector. `k` independent vectors give
  a soundness error of `(1/p)^k`. `k = 2` yields `~2^-122`, which is what the
  precompile ships with.
- Challenge derivation is Fiat–Shamir: `DeriveChallenges(seed, n, k)` folds
  keccak of `seed || (j, i)` into `[0, p)`. In production the seed is
  `keccak(beacon || root || index)` (see `OpeningSeed`), so a prover cannot
  anticipate its challenges before committing the transcript root.

## Public API

Freivalds core (`freivalds.go`):

| symbol | signature | purpose |
| --- | --- | --- |
| `P` | `const uint64 = (1 << 61) - 1` | Field modulus. |
| `Mat` | `struct { Rows, Cols int; Data []int64 }` | Row-major integer matrix. |
| `NewMat` | `func(rows, cols int, data []int64) Mat` | Constructor (panics on length mismatch). |
| `Verify` | `func(a, b, c Mat, r []uint64) bool` | One-vector Freivalds check. |
| `VerifyMulti` | `func(a, b, c Mat, challenges [][]uint64) bool` | k-vector check; false if any fails. |
| `DeriveChallenges` | `func(seed []byte, n, k int) [][]uint64` | Fiat–Shamir challenge derivation. |

Transcript + Merkle (`transcript.go`):

| symbol | signature | purpose |
| --- | --- | --- |
| `DomainMatmulLeaf` | `[]byte("hanzo/poi/matmul-leaf/v1")` | Leaf domain tag. |
| `ExactMatmul` | `func(a, b Mat) Mat` | Whole-K `int64` exact matmul (the proof-bearing GEMM). |
| `MatmulLeaf` | `func(a, b, c Mat) [32]byte` | `keccak(DOMAIN || mat(A) || mat(B) || mat(C))`. |
| `MerkleRoot` | `func(leaves [][32]byte) [32]byte` | Duplicate-last-on-odd keccak fold. |
| `MerkleProof` | `func(leaves [][32]byte, index int) [][32]byte` | Sibling path, bottom-up. |
| `MerkleVerify` | `func(leaf, root [32]byte, index int, proof [][32]byte) bool` | Inclusion check (matches `AICoinMiner._verifyMerkle`). |
| `Opening` | `struct { Index int; A, B, C Mat; Proof [][32]byte }` | What a prover reveals for one matmul. |
| `ProofTranscript` | `struct` w/ `Matmul`, `CommitClaimed`, `Len`, `Root`, `Open` | Append-only commitment to a forward pass's matmuls. |
| `NewTranscript` | `func() *ProofTranscript` | Constructor. |
| `ChallengeIndex` | `func(beacon []byte, root [32]byte, length int) int` | `keccak(beacon || root) mod length`. |
| `OpeningSeed` | `func(beacon []byte, root [32]byte, index int) []byte` | `keccak(beacon || root || BE64(index))`. |
| `VerifyOpening` | `func(root [32]byte, beacon []byte, op Opening, k int) bool` | Merkle inclusion **and** k-vector Freivalds. |

Wire codec + precompile payload (`wire.go`):

| symbol | signature | purpose |
| --- | --- | --- |
| `MaxOpeningDim` | `const = 4096` | Per-dimension bound (see below). |
| `ErrShortOpening`, `ErrOpeningDims` | `error` | Decode errors. |
| `EncodeOpening` | `func(root [32]byte, beacon []byte, op Opening) []byte` | Canonical wire frame. |
| `DecodeOpening` | `func(b []byte) (root [32]byte, beacon []byte, op Opening, err error)` | Bounds-checked parse. |
| `CheckOpening` | `func(input []byte, k int) (included, freivaldsOK bool, err error)` | Precompile payload: decode + verify. |
| `CheckDecoded` | `func(root [32]byte, beacon []byte, op Opening, k int) (bool, bool, error)` | Same, on an already-parsed opening. |
| `FieldOps` | `func(op Opening, k int) uint64` | `k · (t·k + k·n + t·n)` — drives precompile gas. |

## Wire codec

`EncodeOpening` produces (all integers big-endian):

    root[32] | index u64 | beaconLen u32 | beacon | mat(A) | mat(B) | mat(C) | proofLen u32 | proof[32]*

    mat(m) = rows u32 | cols u32 | data[i] as int64-BE   (rows*cols entries)

`DecodeOpening` reverses it, bounds-checking every length. The proof-length
field is capped at 64 (a `2^64`-leaf tree is absurd) to prevent OOM from a
malicious frame; each matrix dimension is capped at `MaxOpeningDim`.

## Bounds

`MaxOpeningDim = 4096`. A full LLM layer is challenged in **slices** no larger
than this, so a malicious frame cannot allocate unboundedly inside the
precompile. In practice a real-model opening is on the order of a few hundred
per side, well under the cap; the constant exists to make the on-chain
decoder's worst-case allocation finite and known.

## Worked example

Prover commits two matmuls, opens the second, encodes it, hands the bytes to a
verifier that decodes and checks:

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/luxfi/crypto/poi"
)

func main() {
	// Prover side: build the exact-integer operands (the int8 accumulators in
	// production; here small int64 values for a runnable demo).
	A := poi.NewMat(2, 3, []int64{1, 2, 3, 4, 5, 6})
	B := poi.NewMat(3, 2, []int64{7, 8, 9, 10, 11, 12})

	// Commit two matmuls to the transcript.
	tr := poi.NewTranscript()
	_ = tr.Matmul(A, B) // index 0
	_ = tr.Matmul(A, B) // index 1
	root := tr.Root()

	// Challenger picks an opening (in production: keccak(beacon || root) mod N).
	beacon := []byte("beacon:demo")
	idx := poi.ChallengeIndex(beacon, root, tr.Len())
	op := tr.Open(idx)

	// Prover ships bytes.
	wire := poi.EncodeOpening(root, beacon, op)

	// Verifier side: decode + check with k=2 challenge vectors.
	rRoot, rBeacon, rOp, err := poi.DecodeOpening(wire)
	if err != nil {
		panic(err)
	}
	included, freivaldsOK, err := poi.CheckDecoded(rRoot, rBeacon, rOp, 2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("root=%s included=%v freivaldsOK=%v\n", hex.EncodeToString(rRoot[:8]), included, freivaldsOK)
	// Expected: included=true freivaldsOK=true
}
```

Fraud path: mutate `rOp.C.Data[0]` before `CheckDecoded` and the second
return flips to `false` with probability `>= 1 - (1/p)^2 ~ 1 - 2^-122`. The
on-chain gate reads that as `included && !freivaldsOK` and slashes.

## References

- **LP-5300** — Thinking Chains / Cognitive Consensus / Proof-of-Thought.
  §Security is what this package operationalizes: the audit-ability promise
  is only real because a third party can decode an opening and rerun
  `CheckDecoded` against the on-chain root.
- **LP-5301** — AIVMBridge. The `computeproof` precompile consumes exactly
  the wire format above.
- **`luxfi/precompile/aivmbridge/computeproof.go`** — line 17,
  `import "github.com/luxfi/crypto/poi"`. That file is the sole in-tree caller
  of `CheckOpening`; keep the two in lockstep when changing the wire.
- **`hanzo-engine/src/poi.rs`** — the Rust prover-side mirror. Byte-for-byte
  identical serialization and keccak fold; an opening produced there verifies
  here (and on-chain) without re-hashing.
