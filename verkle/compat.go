// Package verkle compatibility layer for ethereum/go-verkle migration
package verkle

import (
	"fmt"

	"github.com/luxfi/crypto/ipa/banderwagon"
	"github.com/luxfi/crypto/ipa/bandersnatch/fr"
)

// Type aliases for compatibility with ethereum/go-verkle

// Fr is an alias for field element (compatible with go-verkle)
type Fr = fr.Element

// CRS represents the Common Reference String
type CRS struct {
	G1 []banderwagon.Element
}

// Tree represents a Verkle tree (stub for compatibility)
type Tree struct {
	root *Commitment
}

// NewTree creates a new Verkle tree
func NewTree() *Tree {
	return &Tree{}
}

// Root returns the root commitment
func (t *Tree) Root() *Commitment {
	return t.root
}

// SetRoot sets the root commitment
func (t *Tree) SetRoot(root *Commitment) {
	t.root = root
}

// Node represents a Verkle tree node (stub for compatibility)
type Node interface {
	Commitment() *Commitment
}

// InternalNode represents an internal node
type InternalNode struct {
	commitment *Commitment
	children   [256]Node
}

// Commitment returns the node's commitment
func (n *InternalNode) Commitment() *Commitment {
	return n.commitment
}

// LeafNode represents a leaf node
type LeafNode struct {
	commitment *Commitment
	values     [256][]byte
}

// Commitment returns the leaf's commitment
func (l *LeafNode) Commitment() *Commitment {
	return l.commitment
}

// UnknownNode represents an unknown node
type UnknownNode struct {
	commitment *Commitment
}

// Commitment returns the unknown node's commitment
func (u *UnknownNode) Commitment() *Commitment {
	return u.commitment
}

// SuffixTree compatibility (used in go-verkle)
type SuffixTree struct {
	root Node
}

// NewSuffixTree creates a new suffix tree
func NewSuffixTree() *SuffixTree {
	return &SuffixTree{}
}

// StatelessNode compatibility
type StatelessNode struct {
	commitment *Commitment
}

// Serialize compatibility functions

// SerializeCommitment serializes a commitment (go-verkle compatible)
func SerializeCommitment(c *Commitment) []byte {
	return c.Bytes()
}

// DeserializeCommitment deserializes a commitment (go-verkle compatible)
func DeserializeCommitment(data []byte) (*Commitment, error) {
	c := &Commitment{}
	err := c.SetBytes(data)
	return c, err
}

// SerializeProof serializes a proof (go-verkle compatible)
func SerializeProof(proof *IPAProof) []byte {
	return proof.Bytes()
}

// DeserializeProof deserializes a proof (go-verkle compatible)
func DeserializeProof(data []byte) (*IPAProof, error) {
	proof := &IPAProof{}
	err := proof.SetBytes(data)
	return proof, err
}

// Utility functions for go-verkle compatibility

// GetTreeKey computes a tree key from stem and suffix
func GetTreeKey(stem []byte, suffix byte) []byte {
	key := make([]byte, len(stem)+1)
	copy(key, stem)
	key[len(stem)] = suffix
	return key
}

// GetTreeKeyWithEvaluationAddress computes tree key with evaluation
func GetTreeKeyWithEvaluationAddress(address []byte, treeIndex []byte, subIndex byte) []byte {
	key := make([]byte, 0, 32)
	key = append(key, address...)
	key = append(key, treeIndex...)
	key = append(key, subIndex)
	return key
}

// KeyToStem extracts the stem from a key
func KeyToStem(key []byte) []byte {
	if len(key) < 31 {
		return key
	}
	return key[:31]
}

// StemToKey converts a stem to a key
func StemToKey(stem []byte) []byte {
	key := make([]byte, 32)
	copy(key, stem)
	return key
}

// Configuration compatibility

// Config256 represents a 256-width Verkle configuration
var Config256 = &Config{
	NodeWidth:            256,
	UsePrecomputedTables: true,
}

// MakeVerkleMultiProof creates a multiproof (go-verkle compatible)
func MakeVerkleMultiProof(root *Commitment, keys [][]byte, values [][]byte) (*MultiProof, error) {
	// This is a simplified implementation
	// In practice, this would traverse the tree and create proper proofs
	
	// Convert keys to points
	points := make([]Scalar, len(keys))
	for i, key := range keys {
		points[i] = Hash(key)
	}
	
	// Convert values to scalars
	evaluations := make([][]Scalar, 1) // Simplified: single polynomial
	evaluations[0] = make([]Scalar, len(values))
	for i, value := range values {
		if len(value) > 0 {
			evaluations[0][i] = Hash(value)
		}
	}
	
	// Create multiproof
	prover := NewProver(nil)
	return prover.CreateMultiProof([]*Commitment{root}, evaluations, points)
}

// VerifyVerkleProof verifies a Verkle proof (go-verkle compatible)
func VerifyVerkleProof(proof *MultiProof, Cs []*Commitment, indices []uint8, ys [][]byte) error {
	// Convert to our format
	points := make([]Scalar, len(indices))
	for i, idx := range indices {
		var s Scalar
		s.SetUint64(uint64(idx))
		points[i] = s
	}
	
	evaluations := make([][]Scalar, len(Cs))
	for i := range Cs {
		evaluations[i] = make([]Scalar, len(ys))
		for j, y := range ys {
			if len(y) > 0 {
				evaluations[i][j] = Hash(y)
			}
		}
	}
	
	verifier := NewVerifier(nil)
	return verifier.VerifyMultiProof(Cs, proof, points, evaluations)
}

// GetConfig returns the Verkle configuration (go-verkle compatible)
func GetConfig() *Config {
	return Config256
}

// FromLEBytes creates a scalar from little-endian bytes (go-verkle compatible)
func FromLEBytes(data []byte) (Scalar, error) {
	// Convert from LE to BE
	be := make([]byte, len(data))
	for i := range data {
		be[i] = data[len(data)-1-i]
	}
	return ScalarFromBytes(be)
}

// ToLEBytes converts a scalar to little-endian bytes (go-verkle compatible)
func ToLEBytes(s *Scalar) []byte {
	be := s.Bytes()
	le := make([]byte, len(be))
	for i := range be {
		le[i] = be[len(be)-1-i]
	}
	return le
}

// Element compatibility (for crate-crypto/go-ipa migration)

// Element represents a Banderwagon element (crate-crypto compatible)
type Element = banderwagon.Element

// Identity returns the identity element (crate-crypto compatible)
func Identity() *Element {
	var e Element
	e.Identity()
	return &e
}

// Generator returns the generator (crate-crypto compatible)
func Generator() *Element {
	return banderwagon.GetGenerator()
}

// MapToScalarField maps bytes to scalar field (crate-crypto compatible)
func MapToScalarField(data []byte) Fr {
	return Hash(data)
}

// HashToCurve hashes to a curve point (crate-crypto compatible)
func HashToCurve(data []byte) *Element {
	return banderwagon.HashToElement(data)
}

// NewElement creates a new element from coordinates (crate-crypto compatible)
func NewElement() *Element {
	return &Element{}
}

// Add adds two elements (crate-crypto compatible)
func Add(p, q *Element) *Element {
	var r Element
	r.Add(p, q)
	return &r
}

// ScalarMul multiplies element by scalar (crate-crypto compatible)
func ScalarMul(p *Element, s *Fr) *Element {
	var r Element
	r.ScalarMul(p, s)
	return &r
}

// MultiScalarMul performs multi-scalar multiplication (crate-crypto compatible)
func MultiScalarMul(points []*Element, scalars []*Fr) *Element {
	if len(points) != len(scalars) {
		panic("points and scalars must have same length")
	}
	
	var result Element
	result.Identity()
	
	for i := range points {
		var term Element
		term.ScalarMul(points[i], scalars[i])
		result.Add(&result, &term)
	}
	
	return &result
}

// BatchNormalize normalizes a batch of elements (crate-crypto compatible)
func BatchNormalize(elements []*Element) {
	// Banderwagon elements are always normalized in affine form
	// This is a no-op for compatibility
}

// Error types for compatibility
var (
	ErrInvalidProof      = fmt.Errorf("invalid proof")
	ErrInvalidCommitment = fmt.Errorf("invalid commitment")
	ErrInvalidWitness    = fmt.Errorf("invalid witness")
)