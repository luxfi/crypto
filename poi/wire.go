// Proof-of-Inference opening WIRE CODEC — the bytes a prover/challenger hands to the
// `aivmbridge` compute-proof precompile (and that the off-chain watcher exchanges). One encoding,
// shared by the Go prover, the precompile, and the Solidity reference (ComputeWitnessLib), so a
// real-model-sized opening is verified NATIVELY on-chain (cheap) instead of in gas-bounded EVM
// bytecode. CheckOpening is exactly the precompile's payload: decode → (Merkle inclusion,
// Freivalds) — the two bits the on-chain gate needs to tell an honest opening from a fraud.
package poi

import (
	"encoding/binary"
	"errors"
)

var (
	ErrShortOpening = errors.New("poi: opening wire frame truncated")
	ErrOpeningDims  = errors.New("poi: opening matrix dims overflow or mismatch")
)

// MaxOpeningDim bounds any opened matrix dimension so a malicious frame cannot allocate
// unboundedly inside the precompile. A full layer is challenged in slices ≤ this.
const MaxOpeningDim = 4096

// EncodeOpening serializes (root, beacon, op) into the canonical wire frame:
//
//	root[32] | index u64 | beaconLen u32 | beacon | mat(A) | mat(B) | mat(C) | proofLen u32 | proof[32]*
//	mat(m) = rows u32 | cols u32 | data[i] int64-BE   (rows*cols entries)
func EncodeOpening(root [32]byte, beacon []byte, op Opening) []byte {
	out := make([]byte, 0, 32+8+4+len(beacon)+matWire(op.A)+matWire(op.B)+matWire(op.C)+4+len(op.Proof)*32)
	out = append(out, root[:]...)
	out = appendU64(out, uint64(op.Index))
	out = appendU32(out, uint32(len(beacon)))
	out = append(out, beacon...)
	out = appendMat(out, op.A)
	out = appendMat(out, op.B)
	out = appendMat(out, op.C)
	out = appendU32(out, uint32(len(op.Proof)))
	for _, p := range op.Proof {
		out = append(out, p[:]...)
	}
	return out
}

// DecodeOpening parses the wire frame produced by EncodeOpening, bounds-checking every length.
func DecodeOpening(b []byte) (root [32]byte, beacon []byte, op Opening, err error) {
	p := 0
	read := func(n int) ([]byte, bool) {
		if p+n > len(b) {
			return nil, false
		}
		s := b[p : p+n]
		p += n
		return s, true
	}
	s, ok := read(32)
	if !ok {
		return root, nil, op, ErrShortOpening
	}
	copy(root[:], s)
	if s, ok = read(8); !ok {
		return root, nil, op, ErrShortOpening
	}
	op.Index = int(binary.BigEndian.Uint64(s))
	if s, ok = read(4); !ok {
		return root, nil, op, ErrShortOpening
	}
	bl := int(binary.BigEndian.Uint32(s))
	if beacon, ok = read(bl); !ok {
		return root, nil, op, ErrShortOpening
	}
	if op.A, err = readMat(b, &p); err != nil {
		return root, nil, op, err
	}
	if op.B, err = readMat(b, &p); err != nil {
		return root, nil, op, err
	}
	if op.C, err = readMat(b, &p); err != nil {
		return root, nil, op, err
	}
	if s, ok = read(4); !ok {
		return root, nil, op, ErrShortOpening
	}
	pl := int(binary.BigEndian.Uint32(s))
	if pl > 64 { // a 2^64-leaf tree is absurd; bounds the proof
		return root, nil, op, ErrOpeningDims
	}
	op.Proof = make([][32]byte, pl)
	for i := 0; i < pl; i++ {
		if s, ok = read(32); !ok {
			return root, nil, op, ErrShortOpening
		}
		copy(op.Proof[i][:], s)
	}
	return root, beacon, op, nil
}

// CheckOpening is THE PRECOMPILE PAYLOAD. It decodes an opening and returns the two facts the gate
// needs: `included` (the operands are committed under root — Merkle inclusion) and `freivaldsOK`
// (C == A·B for k beacon-bound challenges). The contract derives:
//   - a genuine opening  = included && freivaldsOK   (verifyOpening), and
//   - a fraud proof      = included && !freivaldsOK  (provesFraud)
//
// so one native call serves both the honest-attest and the slash paths.
func CheckOpening(input []byte, k int) (included bool, freivaldsOK bool, err error) {
	root, beacon, op, err := DecodeOpening(input)
	if err != nil {
		return false, false, err
	}
	return CheckDecoded(root, beacon, op, k)
}

// CheckDecoded is CheckOpening on an ALREADY-PARSED opening — the precompile decodes once (to
// charge gas by the Freivalds work) and then runs the check without re-parsing.
func CheckDecoded(root [32]byte, beacon []byte, op Opening, k int) (included bool, freivaldsOK bool, err error) {
	if op.A.Cols != op.B.Rows || op.B.Cols != op.C.Cols || op.A.Rows != op.C.Rows {
		return false, false, ErrOpeningDims
	}
	included = MerkleVerify(MatmulLeaf(op.A, op.B, op.C), root, op.Index, op.Proof)
	if !included {
		return false, false, nil // not the prover's matmul — neither attest nor fraud
	}
	seed := OpeningSeed(beacon, root, op.Index)
	freivaldsOK = VerifyMulti(op.A, op.B, op.C, DeriveChallenges(seed, op.B.Cols, k))
	return included, freivaldsOK, nil
}

// FieldOps is the Freivalds work an opening costs — drives the precompile gas (O(tk+kn+tn) per
// challenge vector). Pure arithmetic on the decoded dims; safe to call before the heavy check.
func FieldOps(op Opening, k int) uint64 {
	t, kk, n := uint64(op.A.Rows), uint64(op.A.Cols), uint64(op.B.Cols)
	return uint64(k) * (t*kk + kk*n + t*n)
}

// --- internal wire helpers ---------------------------------------------------

func appendU32(b []byte, v uint32) []byte {
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], v)
	return append(b, u[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], v)
	return append(b, u[:]...)
}

func matWire(m Mat) int { return 8 + len(m.Data)*8 }

func appendMat(b []byte, m Mat) []byte {
	b = appendU32(b, uint32(m.Rows))
	b = appendU32(b, uint32(m.Cols))
	var u [8]byte
	for _, x := range m.Data {
		binary.BigEndian.PutUint64(u[:], uint64(x))
		b = append(b, u[:]...)
	}
	return b
}

func readMat(b []byte, p *int) (Mat, error) {
	if *p+8 > len(b) {
		return Mat{}, ErrShortOpening
	}
	rows := int(binary.BigEndian.Uint32(b[*p : *p+4]))
	cols := int(binary.BigEndian.Uint32(b[*p+4 : *p+8]))
	*p += 8
	if rows <= 0 || cols <= 0 || rows > MaxOpeningDim || cols > MaxOpeningDim {
		return Mat{}, ErrOpeningDims
	}
	n := rows * cols
	if *p+n*8 > len(b) {
		return Mat{}, ErrShortOpening
	}
	data := make([]int64, n)
	for i := 0; i < n; i++ {
		data[i] = int64(binary.BigEndian.Uint64(b[*p : *p+8]))
		*p += 8
	}
	return NewMat(rows, cols, data), nil
}
