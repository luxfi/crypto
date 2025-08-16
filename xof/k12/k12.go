// Package k12 provides KangarooTwelve (K12) extendable output function implementation
// based on Cloudflare CIRCL library. K12 is 7x faster than SHAKE for large data.
package k12

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/cloudflare/circl/xof/k12"
)

// DigestLength represents common output lengths for K12
const (
	DigestLength128 = 16  // 128 bits
	DigestLength256 = 32  // 256 bits
	DigestLength384 = 48  // 384 bits
	DigestLength512 = 64  // 512 bits
	DigestLength1024 = 128 // 1024 bits
)

// State represents a K12 hasher state
type State struct {
	k12 *k12.State
}

// NewState creates a new K12 state
func NewState() *State {
	return &State{
		k12: k12.NewState(),
	}
}

// NewDraft10 creates a K12 state using draft-10 version
func NewDraft10(domainSeparation []byte) *State {
	return &State{
		k12: k12.NewDraft10(domainSeparation),
	}
}

// Write absorbs more data into the K12 state
func (s *State) Write(p []byte) (n int, err error) {
	return s.k12.Write(p)
}

// Read squeezes output from the K12 state
func (s *State) Read(p []byte) (n int, err error) {
	return s.k12.Read(p)
}

// Reset resets the K12 state to initial
func (s *State) Reset() {
	s.k12.Reset()
}

// Clone creates a copy of the K12 state
func (s *State) Clone() *State {
	return &State{
		k12: s.k12.Clone(),
	}
}

// Sum appends the current hash to b and returns the resulting slice
func (s *State) Sum(b []byte, outputLen int) []byte {
	clone := s.Clone()
	output := make([]byte, outputLen)
	clone.Read(output)
	return append(b, output...)
}

// Hash is a convenience function that hashes data and returns the output
func Hash(data []byte, outputLen int) []byte {
	state := NewState()
	state.Write(data)
	output := make([]byte, outputLen)
	state.Read(output)
	return output
}

// HashWithCustomization hashes data with domain separation
func HashWithCustomization(data, customization []byte, outputLen int) []byte {
	state := NewDraft10(customization)
	state.Write(data)
	output := make([]byte, outputLen)
	state.Read(output)
	return output
}

// Hasher implements the hash.Hash interface for K12
type Hasher struct {
	state     *State
	outputLen int
}

// NewHasher creates a new K12 hasher with specified output length
func NewHasher(outputLen int) *Hasher {
	return &Hasher{
		state:     NewState(),
		outputLen: outputLen,
	}
}

// NewHasher256 creates a K12 hasher with 256-bit output
func NewHasher256() *Hasher {
	return NewHasher(DigestLength256)
}

// NewHasher512 creates a K12 hasher with 512-bit output
func NewHasher512() *Hasher {
	return NewHasher(DigestLength512)
}

// Write adds more data to the running hash
func (h *Hasher) Write(p []byte) (n int, err error) {
	return h.state.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice
func (h *Hasher) Sum(b []byte) []byte {
	return h.state.Sum(b, h.outputLen)
}

// Reset resets the hasher to its initial state
func (h *Hasher) Reset() {
	h.state.Reset()
}

// Size returns the number of bytes Sum will return
func (h *Hasher) Size() int {
	return h.outputLen
}

// BlockSize returns the hash's underlying block size
func (h *Hasher) BlockSize() int {
	return 168 // K12 uses a rate of 168 bytes
}

// XOF implements an extendable output function based on K12
type XOF struct {
	state *State
}

// NewXOF creates a new K12 XOF
func NewXOF() *XOF {
	return &XOF{
		state: NewState(),
	}
}

// Write absorbs more data
func (x *XOF) Write(p []byte) (n int, err error) {
	return x.state.Write(p)
}

// Read squeezes arbitrary amount of output
func (x *XOF) Read(p []byte) (n int, err error) {
	return x.state.Read(p)
}

// Reset resets the XOF to initial state
func (x *XOF) Reset() {
	x.state.Reset()
}

// Clone creates a copy of the XOF
func (x *XOF) Clone() *XOF {
	return &XOF{
		state: x.state.Clone(),
	}
}

// MerkleTree provides K12-based Merkle tree operations
type MerkleTree struct {
	leaves [][]byte
	nodes  [][]byte
	depth  int
}

// NewMerkleTree creates a new K12-based Merkle tree
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{
		leaves: make([][]byte, 0),
		nodes:  make([][]byte, 0),
	}
}

// AddLeaf adds a leaf to the Merkle tree
func (m *MerkleTree) AddLeaf(data []byte) {
	leafHash := Hash(data, DigestLength256)
	m.leaves = append(m.leaves, leafHash)
}

// ComputeRoot computes the Merkle tree root
func (m *MerkleTree) ComputeRoot() ([]byte, error) {
	if len(m.leaves) == 0 {
		return nil, errors.New("no leaves in tree")
	}
	
	// Copy leaves to working set
	current := make([][]byte, len(m.leaves))
	copy(current, m.leaves)
	
	// Build tree level by level
	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+1)/2)
		
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				// Hash pair
				combined := append(current[i], current[i+1]...)
				next = append(next, Hash(combined, DigestLength256))
			} else {
				// Odd leaf, promote to next level
				next = append(next, current[i])
			}
		}
		
		m.nodes = append(m.nodes, current...)
		current = next
	}
	
	return current[0], nil
}

// Commitment provides K12-based commitment scheme
type Commitment struct {
	state *State
}

// NewCommitment creates a new K12-based commitment
func NewCommitment() *Commitment {
	return &Commitment{
		state: NewState(),
	}
}

// Commit creates a commitment to data with a nonce
func (c *Commitment) Commit(data, nonce []byte) []byte {
	c.state.Reset()
	c.state.Write(nonce)
	c.state.Write(data)
	
	commitment := make([]byte, DigestLength256)
	c.state.Read(commitment)
	return commitment
}

// Verify verifies a commitment
func (c *Commitment) Verify(data, nonce, commitment []byte) bool {
	computed := c.Commit(data, nonce)
	
	if len(computed) != len(commitment) {
		return false
	}
	
	// Constant-time comparison
	result := byte(0)
	for i := range computed {
		result |= computed[i] ^ commitment[i]
	}
	return result == 0
}

// KDF provides K12-based key derivation function
type KDF struct {
	state *State
}

// NewKDF creates a new K12-based KDF
func NewKDF() *KDF {
	return &KDF{
		state: NewState(),
	}
}

// DeriveKey derives a key from input material
func (k *KDF) DeriveKey(inputMaterial, salt, info []byte, outputLen int) []byte {
	k.state.Reset()
	
	// Write salt
	if len(salt) > 0 {
		k.state.Write(salt)
	}
	
	// Write input material
	k.state.Write(inputMaterial)
	
	// Write info
	if len(info) > 0 {
		k.state.Write(info)
	}
	
	// Write output length as domain separation
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(outputLen))
	k.state.Write(lenBytes)
	
	// Generate output
	output := make([]byte, outputLen)
	k.state.Read(output)
	return output
}

// MAC provides K12-based message authentication code
type MAC struct {
	key []byte
}

// NewMAC creates a new K12-based MAC
func NewMAC(key []byte) *MAC {
	return &MAC{
		key: key,
	}
}

// Sum computes MAC for a message
func (m *MAC) Sum(message []byte) []byte {
	state := NewState()
	
	// Write key
	state.Write(m.key)
	
	// Write message length
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, uint64(len(message)))
	state.Write(lenBytes)
	
	// Write message
	state.Write(message)
	
	// Generate MAC
	mac := make([]byte, DigestLength256)
	state.Read(mac)
	return mac
}

// Verify verifies a MAC
func (m *MAC) Verify(message, mac []byte) bool {
	computed := m.Sum(message)
	
	if len(computed) != len(mac) {
		return false
	}
	
	// Constant-time comparison
	result := byte(0)
	for i := range computed {
		result |= computed[i] ^ mac[i]
	}
	return result == 0
}

// Stream provides K12-based stream cipher
type Stream struct {
	state *State
	buf   []byte
	pos   int
}

// NewStream creates a new K12-based stream cipher
func NewStream(key, nonce []byte) *Stream {
	state := NewState()
	state.Write(key)
	state.Write(nonce)
	
	return &Stream{
		state: state,
		buf:   make([]byte, 1024),
		pos:   1024, // Force initial fill
	}
}

// XORKeyStream XORs each byte in the given slice with a byte from the cipher stream
func (s *Stream) XORKeyStream(dst, src []byte) {
	for i := range src {
		if s.pos >= len(s.buf) {
			s.state.Read(s.buf)
			s.pos = 0
		}
		dst[i] = src[i] ^ s.buf[s.pos]
		s.pos++
	}
}

// BatchHash hashes multiple inputs in parallel (simulated)
func BatchHash(inputs [][]byte, outputLen int) [][]byte {
	outputs := make([][]byte, len(inputs))
	for i, input := range inputs {
		outputs[i] = Hash(input, outputLen)
	}
	return outputs
}

// TreeHash computes a tree hash over chunks of data
func TreeHash(data []byte, chunkSize, outputLen int) []byte {
	if len(data) <= chunkSize {
		return Hash(data, outputLen)
	}
	
	// Split into chunks and hash
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunkHash := Hash(data[i:end], outputLen)
		chunks = append(chunks, chunkHash)
	}
	
	// Recursively hash chunks
	for len(chunks) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(chunks); i += 2 {
			if i+1 < len(chunks) {
				combined := append(chunks[i], chunks[i+1]...)
				nextLevel = append(nextLevel, Hash(combined, outputLen))
			} else {
				nextLevel = append(nextLevel, chunks[i])
			}
		}
		chunks = nextLevel
	}
	
	return chunks[0]
}

// Ensure interfaces are satisfied
var (
	_ hash.Hash = (*Hasher)(nil)
	_ io.Writer = (*State)(nil)
	_ io.Reader = (*State)(nil)
	_ io.Writer = (*XOF)(nil)
	_ io.Reader = (*XOF)(nil)
)

// Version returns the K12 implementation version
func Version() string {
	return "1.0.0-circl"
}

// BenchmarkHash provides a simple benchmark helper
func BenchmarkHash(data []byte, iterations int) ([]byte, error) {
	if iterations <= 0 {
		return nil, fmt.Errorf("iterations must be positive")
	}
	
	var result []byte
	for i := 0; i < iterations; i++ {
		result = Hash(data, DigestLength256)
	}
	return result, nil
}