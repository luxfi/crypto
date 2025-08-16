package verkle

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Precompile addresses for Verkle operations
var (
	PedersenCommitAddress    = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	IPAVerifyAddress        = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}
	MultiproofVerifyAddress = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02}
	StemCommitAddress       = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03}
	TreeHashAddress         = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04}
	WitnessVerifyAddress    = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05}
)

// Gas costs for Verkle operations
const (
	PedersenCommitGas    = 50000
	IPAVerifyGas        = 200000
	MultiproofVerifyGas = 300000
	StemCommitGas       = 40000
	TreeHashGas         = 20000
	WitnessVerifyGas    = 500000
	
	// Per-unit costs
	PerScalarGas = 1000
	PerPointGas  = 2000
	PerProofGas  = 3000
)

// PedersenCommitPrecompile computes Pedersen commitments
type PedersenCommitPrecompile struct{}

// RequiredGas calculates gas for Pedersen commitment
func (p *PedersenCommitPrecompile) RequiredGas(input []byte) uint64 {
	numScalars := len(input) / 32
	return PedersenCommitGas + uint64(numScalars)*PerScalarGas
}

// Run executes Pedersen commitment
// Input format: [scalar1(32)][scalar2(32)]...[scalarN(32)]
// Output format: [commitment(32)]
func (p *PedersenCommitPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input)%32 != 0 {
		return nil, errors.New("invalid input length for Pedersen commitment")
	}
	
	numScalars := len(input) / 32
	if numScalars > 256 {
		return nil, errors.New("too many scalars for Pedersen commitment")
	}
	
	// Parse scalars
	scalars := make([]Scalar, numScalars)
	for i := 0; i < numScalars; i++ {
		scalar, err := ScalarFromBytes(input[i*32 : (i+1)*32])
		if err != nil {
			return nil, fmt.Errorf("invalid scalar at index %d: %w", i, err)
		}
		scalars[i] = scalar
	}
	
	// Compute commitment
	commitment := PedersenCommit(scalars)
	
	return commitment.Bytes(), nil
}

// IPAVerifyPrecompile verifies IPA proofs
type IPAVerifyPrecompile struct{}

// RequiredGas calculates gas for IPA verification
func (i *IPAVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return IPAVerifyGas
}

// Run executes IPA proof verification
// Input format: [commitment(32)][proof_len(2)][proof][point(32)][evaluation(32)]
// Output format: [valid(1)] where 1=valid, 0=invalid
func (i *IPAVerifyPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 66 { // 32 + 2 + 32 + 32 minimum
		return nil, errors.New("input too short for IPA verification")
	}
	
	// Parse commitment
	commitment := &Commitment{}
	if err := commitment.SetBytes(input[:32]); err != nil {
		return nil, fmt.Errorf("invalid commitment: %w", err)
	}
	
	// Parse proof length and proof
	proofLen := binary.BigEndian.Uint16(input[32:34])
	if len(input) < int(34+proofLen+64) {
		return nil, errors.New("insufficient input for proof and parameters")
	}
	
	proof := &IPAProof{}
	if err := proof.SetBytes(input[34 : 34+proofLen]); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	
	// Parse point and evaluation
	offset := 34 + proofLen
	point, err := ScalarFromBytes(input[offset : offset+32])
	if err != nil {
		return nil, fmt.Errorf("invalid point: %w", err)
	}
	
	evaluation, err := ScalarFromBytes(input[offset+32 : offset+64])
	if err != nil {
		return nil, fmt.Errorf("invalid evaluation: %w", err)
	}
	
	// Verify proof
	verifier := NewVerifier(nil)
	if err := verifier.VerifyIPAProof(commitment, proof, point, evaluation); err != nil {
		return []byte{0}, nil // Invalid
	}
	
	return []byte{1}, nil // Valid
}

// MultiproofVerifyPrecompile verifies multiproofs
type MultiproofVerifyPrecompile struct{}

// RequiredGas calculates gas for multiproof verification
func (m *MultiproofVerifyPrecompile) RequiredGas(input []byte) uint64 {
	// Estimate based on input size
	return MultiproofVerifyGas + uint64(len(input)/32)*PerScalarGas
}

// Run executes multiproof verification
// Input format: [num_commitments(2)][commitments][proof_len(2)][proof][num_points(2)][points][evaluations]
// Output format: [valid(1)]
func (m *MultiproofVerifyPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 6 {
		return nil, errors.New("input too short for multiproof")
	}
	
	offset := 0
	
	// Parse number of commitments
	numCommitments := binary.BigEndian.Uint16(input[offset : offset+2])
	offset += 2
	
	// Parse commitments
	commitments := make([]*Commitment, numCommitments)
	for i := uint16(0); i < numCommitments; i++ {
		if offset+32 > len(input) {
			return nil, errors.New("insufficient input for commitments")
		}
		commitments[i] = &Commitment{}
		if err := commitments[i].SetBytes(input[offset : offset+32]); err != nil {
			return nil, fmt.Errorf("invalid commitment %d: %w", i, err)
		}
		offset += 32
	}
	
	// Parse proof
	if offset+2 > len(input) {
		return nil, errors.New("insufficient input for proof length")
	}
	proofLen := binary.BigEndian.Uint16(input[offset : offset+2])
	offset += 2
	
	if offset+int(proofLen) > len(input) {
		return nil, errors.New("insufficient input for proof")
	}
	proof := &MultiProof{}
	if err := proof.SetBytes(input[offset : offset+int(proofLen)]); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	offset += int(proofLen)
	
	// Parse points
	if offset+2 > len(input) {
		return nil, errors.New("insufficient input for points count")
	}
	numPoints := binary.BigEndian.Uint16(input[offset : offset+2])
	offset += 2
	
	points := make([]Scalar, numPoints)
	for i := uint16(0); i < numPoints; i++ {
		if offset+32 > len(input) {
			return nil, errors.New("insufficient input for points")
		}
		point, err := ScalarFromBytes(input[offset : offset+32])
		if err != nil {
			return nil, fmt.Errorf("invalid point %d: %w", i, err)
		}
		points[i] = point
		offset += 32
	}
	
	// Parse evaluations (remaining input)
	// Evaluations are organized as [num_commitments][num_points] matrix
	evaluations := make([][]Scalar, numCommitments)
	for i := uint16(0); i < numCommitments; i++ {
		evaluations[i] = make([]Scalar, numPoints)
		for j := uint16(0); j < numPoints; j++ {
			if offset+32 > len(input) {
				return nil, errors.New("insufficient input for evaluations")
			}
			eval, err := ScalarFromBytes(input[offset : offset+32])
			if err != nil {
				return nil, fmt.Errorf("invalid evaluation [%d][%d]: %w", i, j, err)
			}
			evaluations[i][j] = eval
			offset += 32
		}
	}
	
	// Verify multiproof
	verifier := NewVerifier(nil)
	if err := verifier.VerifyMultiProof(commitments, proof, points, evaluations); err != nil {
		return []byte{0}, nil // Invalid
	}
	
	return []byte{1}, nil // Valid
}

// StemCommitPrecompile computes stem commitments
type StemCommitPrecompile struct{}

// RequiredGas calculates gas for stem commitment
func (s *StemCommitPrecompile) RequiredGas(input []byte) uint64 {
	return StemCommitGas + uint64(len(input)/32)*PerScalarGas
}

// Run executes stem commitment
// Input format: [stem(32)][value1(32)][value2(32)]...[valueN(32)]
// Output format: [commitment(32)]
func (s *StemCommitPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 64 || (len(input)-32)%32 != 0 {
		return nil, errors.New("invalid input length for stem commitment")
	}
	
	// Parse stem
	stem := input[:32]
	
	// Parse values
	numValues := (len(input) - 32) / 32
	values := make([]Scalar, numValues)
	for i := 0; i < numValues; i++ {
		value, err := ScalarFromBytes(input[32+i*32 : 32+(i+1)*32])
		if err != nil {
			return nil, fmt.Errorf("invalid value at index %d: %w", i, err)
		}
		values[i] = value
	}
	
	// Compute stem commitment
	commitment := StemCommitment(stem, values)
	
	return commitment.Bytes(), nil
}

// TreeHashPrecompile computes tree hashes
type TreeHashPrecompile struct{}

// RequiredGas calculates gas for tree hashing
func (t *TreeHashPrecompile) RequiredGas(input []byte) uint64 {
	numChildren := len(input) / 32
	return TreeHashGas + uint64(numChildren)*PerPointGas
}

// Run executes tree hashing
// Input format: [child1(32)][child2(32)]...[childN(32)]
// Output format: [hash(32)]
func (t *TreeHashPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input)%32 != 0 {
		return nil, errors.New("invalid input length for tree hash")
	}
	
	numChildren := len(input) / 32
	children := make([]*Commitment, numChildren)
	
	for i := 0; i < numChildren; i++ {
		childBytes := input[i*32 : (i+1)*32]
		// Check if child is zero (empty)
		isZero := true
		for _, b := range childBytes {
			if b != 0 {
				isZero = false
				break
			}
		}
		
		if !isZero {
			children[i] = &Commitment{}
			if err := children[i].SetBytes(childBytes); err != nil {
				return nil, fmt.Errorf("invalid child at index %d: %w", i, err)
			}
		}
	}
	
	// Compute tree hash
	hash := TreeHash(children)
	
	return hash.Bytes(), nil
}

// WitnessVerifyPrecompile verifies complete witnesses
type WitnessVerifyPrecompile struct{}

// RequiredGas calculates gas for witness verification
func (w *WitnessVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return WitnessVerifyGas
}

// Run executes witness verification
// Input format: [root(32)][num_levels(2)][witness_data...]
// Witness data: For each level: [commitment(32)][proof_len(2)][proof][value(32)][index(4)]
// Output format: [valid(1)]
func (w *WitnessVerifyPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 34 {
		return nil, errors.New("input too short for witness")
	}
	
	// Parse root
	root := &Commitment{}
	if err := root.SetBytes(input[:32]); err != nil {
		return nil, fmt.Errorf("invalid root: %w", err)
	}
	
	// Parse number of levels
	numLevels := binary.BigEndian.Uint16(input[32:34])
	
	// Parse witness data
	witness := &Witness{
		Commitments: make([]*Commitment, numLevels),
		Proofs:      make([]*IPAProof, numLevels),
		Values:      make([]Scalar, numLevels),
		Indices:     make([]int, numLevels),
	}
	
	offset := 34
	for i := uint16(0); i < numLevels; i++ {
		if offset+32 > len(input) {
			return nil, fmt.Errorf("insufficient input for commitment %d", i)
		}
		
		// Parse commitment
		witness.Commitments[i] = &Commitment{}
		if err := witness.Commitments[i].SetBytes(input[offset : offset+32]); err != nil {
			return nil, fmt.Errorf("invalid commitment %d: %w", i, err)
		}
		offset += 32
		
		// Parse proof
		if offset+2 > len(input) {
			return nil, fmt.Errorf("insufficient input for proof length %d", i)
		}
		proofLen := binary.BigEndian.Uint16(input[offset : offset+2])
		offset += 2
		
		if offset+int(proofLen) > len(input) {
			return nil, fmt.Errorf("insufficient input for proof %d", i)
		}
		witness.Proofs[i] = &IPAProof{}
		if err := witness.Proofs[i].SetBytes(input[offset : offset+int(proofLen)]); err != nil {
			return nil, fmt.Errorf("invalid proof %d: %w", i, err)
		}
		offset += int(proofLen)
		
		// Parse value
		if offset+32 > len(input) {
			return nil, fmt.Errorf("insufficient input for value %d", i)
		}
		value, err := ScalarFromBytes(input[offset : offset+32])
		if err != nil {
			return nil, fmt.Errorf("invalid value %d: %w", i, err)
		}
		witness.Values[i] = value
		offset += 32
		
		// Parse index
		if offset+4 > len(input) {
			return nil, fmt.Errorf("insufficient input for index %d", i)
		}
		witness.Indices[i] = int(binary.BigEndian.Uint32(input[offset : offset+4]))
		offset += 4
	}
	
	// Verify witness
	if err := VerifyWitness(witness, root); err != nil {
		return []byte{0}, nil // Invalid
	}
	
	return []byte{1}, nil // Valid
}