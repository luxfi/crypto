// Package verkle provides a unified interface for Verkle tree cryptography
// This package wraps our internal IPA implementation and provides compatibility
// with ethereum/go-verkle interfaces to ensure ONE implementation across all packages
package verkle

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
	"github.com/luxfi/crypto/ipa/common"
	"github.com/luxfi/crypto/ipa/ipa"
	multiproof "github.com/luxfi/crypto/ipa"
)

// Config represents Verkle tree configuration
type Config struct {
	// NodeWidth is the width of internal nodes (typically 256)
	NodeWidth int
	// UsePrecomputedTables enables precomputed tables for faster operations
	UsePrecomputedTables bool
}

// DefaultConfig returns the default Verkle configuration
func DefaultConfig() *Config {
	return &Config{
		NodeWidth:            256,
		UsePrecomputedTables: true,
	}
}

// Point represents a Banderwagon point (compatible with go-verkle)
type Point = banderwagon.Element

// Scalar represents a scalar field element
type Scalar = fr.Element

// Commitment represents a Pedersen commitment
type Commitment struct {
	point banderwagon.Element
}

// NewCommitment creates a new commitment from a point
func NewCommitment(point *banderwagon.Element) *Commitment {
	return &Commitment{point: *point}
}

// Bytes returns the commitment as bytes
func (c *Commitment) Bytes() []byte {
	return c.point.Bytes()
}

// SetBytes sets the commitment from bytes
func (c *Commitment) SetBytes(data []byte) error {
	_, err := c.point.SetBytes(data)
	return err
}

// Equal checks if two commitments are equal
func (c *Commitment) Equal(other *Commitment) bool {
	return c.point.Equal(&other.point)
}

// Add adds two commitments
func (c *Commitment) Add(other *Commitment) *Commitment {
	var result banderwagon.Element
	result.Add(&c.point, &other.point)
	return &Commitment{point: result}
}

// ScalarMul multiplies a commitment by a scalar
func (c *Commitment) ScalarMul(scalar *Scalar) *Commitment {
	var result banderwagon.Element
	result.ScalarMul(&c.point, scalar)
	return &Commitment{point: result}
}

// IPAProof represents an Inner Product Argument proof
type IPAProof struct {
	proof ipa.IPAProof
}

// Bytes serializes the proof
func (p *IPAProof) Bytes() []byte {
	data, _ := p.proof.Write()
	return data
}

// SetBytes deserializes the proof
func (p *IPAProof) SetBytes(data []byte) error {
	return p.proof.Read(data)
}

// MultiProof represents a multi-opening proof
type MultiProof struct {
	proof multiproof.MultiProof
}

// Bytes serializes the multiproof
func (m *MultiProof) Bytes() []byte {
	data, _ := m.proof.Write()
	return data
}

// SetBytes deserializes the multiproof
func (m *MultiProof) SetBytes(data []byte) error {
	return m.proof.Read(data)
}

// Prover provides proving capabilities for Verkle trees
type Prover struct {
	config *Config
}

// NewProver creates a new prover
func NewProver(config *Config) *Prover {
	if config == nil {
		config = DefaultConfig()
	}
	return &Prover{config: config}
}

// CreateIPAProof creates an IPA proof for a polynomial commitment
func (p *Prover) CreateIPAProof(commitment *Commitment, evaluations []Scalar, point Scalar) (*IPAProof, error) {
	// Convert to IPA types
	var poly [256]fr.Element
	for i := range evaluations {
		if i >= len(poly) {
			break
		}
		poly[i] = evaluations[i]
	}

	// Create transcript
	transcript := common.NewTranscript("verkle")
	
	// Create IPA config
	ipaConfig := ipa.IPAConfig{
		PrecomputedWeights: p.config.UsePrecomputedTables,
	}

	// Create proof
	ipaProver := ipa.NewIPAProver(ipaConfig)
	proof := ipaProver.CreateProof(transcript, &commitment.point, poly[:], point)

	return &IPAProof{proof: proof}, nil
}

// CreateMultiProof creates a proof for multiple polynomial openings
func (p *Prover) CreateMultiProof(commitments []*Commitment, evaluations [][]Scalar, points []Scalar) (*MultiProof, error) {
	// Convert commitments
	comms := make([]banderwagon.Element, len(commitments))
	for i, c := range commitments {
		comms[i] = c.point
	}

	// Convert evaluations
	evals := make([][]fr.Element, len(evaluations))
	for i, ev := range evaluations {
		evals[i] = make([]fr.Element, len(ev))
		for j, e := range ev {
			evals[i][j] = e
		}
	}

	// Create multiproof
	proof, err := multiproof.CreateMultiProof(comms, evals, points)
	if err != nil {
		return nil, fmt.Errorf("failed to create multiproof: %w", err)
	}

	return &MultiProof{proof: proof}, nil
}

// Verifier provides verification capabilities for Verkle trees
type Verifier struct {
	config *Config
}

// NewVerifier creates a new verifier
func NewVerifier(config *Config) *Verifier {
	if config == nil {
		config = DefaultConfig()
	}
	return &Verifier{config: config}
}

// VerifyIPAProof verifies an IPA proof
func (v *Verifier) VerifyIPAProof(commitment *Commitment, proof *IPAProof, point Scalar, evaluation Scalar) error {
	// Create transcript
	transcript := common.NewTranscript("verkle")
	
	// Create IPA config
	ipaConfig := ipa.IPAConfig{
		PrecomputedWeights: v.config.UsePrecomputedTables,
	}

	// Verify proof
	verifier := ipa.NewIPAVerifier(ipaConfig)
	ok := verifier.VerifyProof(transcript, &commitment.point, &proof.proof, point, evaluation)
	
	if !ok {
		return errors.New("IPA proof verification failed")
	}
	return nil
}

// VerifyMultiProof verifies a multiproof
func (v *Verifier) VerifyMultiProof(commitments []*Commitment, proof *MultiProof, points []Scalar, evaluations [][]Scalar) error {
	// Convert commitments
	comms := make([]banderwagon.Element, len(commitments))
	for i, c := range commitments {
		comms[i] = c.point
	}

	// Convert evaluations
	evals := make([][]fr.Element, len(evaluations))
	for i, ev := range evaluations {
		evals[i] = make([]fr.Element, len(ev))
		for j, e := range ev {
			evals[i][j] = e
		}
	}

	// Verify multiproof
	err := multiproof.VerifyMultiProof(&proof.proof, comms, evals, points)
	if err != nil {
		return fmt.Errorf("multiproof verification failed: %w", err)
	}

	return nil
}

// PedersenCommit computes a Pedersen commitment to a vector
func PedersenCommit(values []Scalar) *Commitment {
	// Convert to banderwagon elements
	var elements [256]fr.Element
	for i := range values {
		if i >= len(elements) {
			break
		}
		elements[i] = values[i]
	}

	// Compute commitment using precomputed bases
	commitment := banderwagon.PedersenCommit(elements[:])
	return &Commitment{point: *commitment}
}

// PedersenCommitSparse computes a Pedersen commitment to a sparse vector
func PedersenCommitSparse(indices []int, values []Scalar) *Commitment {
	if len(indices) != len(values) {
		panic("indices and values must have same length")
	}

	// Create sparse vector
	var elements [256]fr.Element
	for i, idx := range indices {
		if idx >= 0 && idx < len(elements) {
			elements[idx] = values[i]
		}
	}

	// Compute commitment
	commitment := banderwagon.PedersenCommit(elements[:])
	return &Commitment{point: *commitment}
}

// Hash hashes data to a field element (compatible with go-verkle)
func Hash(data []byte) Scalar {
	var result fr.Element
	result.SetBytes(data) // This will reduce modulo the field order
	return result
}

// HashToPoint hashes data to a Banderwagon point
func HashToPoint(data []byte) *Point {
	point := banderwagon.HashToElement(data)
	return point
}

// ScalarFromBigInt converts a big.Int to a Scalar
func ScalarFromBigInt(n *big.Int) Scalar {
	var scalar fr.Element
	scalar.SetBigInt(n)
	return scalar
}

// ScalarFromBytes converts bytes to a Scalar
func ScalarFromBytes(data []byte) (Scalar, error) {
	var scalar fr.Element
	if len(data) != 32 {
		return scalar, fmt.Errorf("invalid scalar length: got %d, want 32", len(data))
	}
	scalar.SetBytes(data)
	return scalar, nil
}

// PointFromBytes converts bytes to a Point
func PointFromBytes(data []byte) (*Point, error) {
	var point banderwagon.Element
	_, err := point.SetBytes(data)
	if err != nil {
		return nil, err
	}
	return &point, nil
}

// StemCommitment computes a commitment for a Verkle tree stem
func StemCommitment(stem []byte, values []Scalar) *Commitment {
	// Hash stem to get base point
	basePoint := HashToPoint(stem)
	
	// Compute weighted sum
	var result banderwagon.Element
	result.Identity()
	
	for i, value := range values {
		var term banderwagon.Element
		term.ScalarMul(basePoint, &value)
		
		// Weight by position
		var weight fr.Element
		weight.SetUint64(uint64(i + 1))
		term.ScalarMul(&term, &weight)
		
		result.Add(&result, &term)
	}
	
	return &Commitment{point: result}
}

// Witness represents a Verkle tree witness
type Witness struct {
	// Commitments at each level
	Commitments []*Commitment
	// Opening proofs
	Proofs []*IPAProof
	// Values being proven
	Values []Scalar
	// Indices in the tree
	Indices []int
}

// VerifyWitness verifies a complete Verkle witness
func VerifyWitness(witness *Witness, root *Commitment) error {
	if len(witness.Commitments) == 0 {
		return errors.New("empty witness")
	}
	
	// Verify root matches
	if !witness.Commitments[0].Equal(root) {
		return errors.New("witness root doesn't match expected root")
	}
	
	// Verify each level
	verifier := NewVerifier(nil)
	for i, proof := range witness.Proofs {
		if i >= len(witness.Commitments) {
			return errors.New("insufficient commitments")
		}
		
		// Extract evaluation point and value
		point := ScalarFromBigInt(big.NewInt(int64(witness.Indices[i])))
		value := witness.Values[i]
		
		// Verify proof
		err := verifier.VerifyIPAProof(witness.Commitments[i], proof, point, value)
		if err != nil {
			return fmt.Errorf("proof verification failed at level %d: %w", i, err)
		}
	}
	
	return nil
}

// TreeHash computes the hash of a Verkle tree node
func TreeHash(children []*Commitment) *Commitment {
	var result banderwagon.Element
	result.Identity()
	
	for i, child := range children {
		if child == nil {
			continue
		}
		
		// Weight by position
		var weight fr.Element
		weight.SetUint64(uint64(i))
		
		var weighted banderwagon.Element
		weighted.ScalarMul(&child.point, &weight)
		result.Add(&result, &weighted)
	}
	
	return &Commitment{point: result}
}

// BatchVerify verifies multiple IPA proofs in batch
func BatchVerify(commitments []*Commitment, proofs []*IPAProof, points []Scalar, evaluations []Scalar) error {
	if len(commitments) != len(proofs) || len(proofs) != len(points) || len(points) != len(evaluations) {
		return errors.New("mismatched input lengths")
	}
	
	// TODO: Implement batch verification using random linear combination
	// For now, verify individually
	verifier := NewVerifier(nil)
	for i := range commitments {
		err := verifier.VerifyIPAProof(commitments[i], proofs[i], points[i], evaluations[i])
		if err != nil {
			return fmt.Errorf("batch verification failed at index %d: %w", i, err)
		}
	}
	
	return nil
}

// GetGenerator returns the generator point for Banderwagon
func GetGenerator() *Point {
	gen := banderwagon.GetGenerator()
	return &gen
}

// GetIdentity returns the identity element
func GetIdentity() *Point {
	var id banderwagon.Element
	id.Identity()
	return &id
}

// Version returns the verkle implementation version
func Version() string {
	return "1.0.0-lux"
}