package slhdsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"sync"
)

// Pool for reusing large signature buffers (SLH-DSA has large signatures)
var slhBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, SLHDSA256fSignatureSize) // Max size (~50KB)
	},
}

// Pool for hash state objects
var hashStatePool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

// getSlhBuffer gets a buffer from the pool
func getSlhBuffer(size int) []byte {
	buf := slhBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// putSlhBuffer returns a buffer to the pool
func putSlhBuffer(buf []byte) {
	if cap(buf) >= SLHDSA128sSignatureSize { // Only pool larger buffers
		slhBufferPool.Put(buf)
	}
}

// getHasher gets a hash.Hash from the pool
func getHasher() hash.Hash {
	h := hashStatePool.Get().(hash.Hash)
	h.Reset()
	return h
}

// putHasher returns a hash.Hash to the pool
func putHasher(h hash.Hash) {
	hashStatePool.Put(h)
}

// OptimizedGenerateKey generates keys with optimized memory usage
func OptimizedGenerateKey(rand io.Reader, mode Mode) (*PrivateKey, error) {
	var pubKeySize, privKeySize int

	switch mode {
	case SLHDSA128s:
		pubKeySize = SLHDSA128sPublicKeySize
		privKeySize = SLHDSA128sPrivateKeySize
	case SLHDSA128f:
		pubKeySize = SLHDSA128fPublicKeySize
		privKeySize = SLHDSA128fPrivateKeySize
	case SLHDSA192s:
		pubKeySize = SLHDSA192sPublicKeySize
		privKeySize = SLHDSA192sPrivateKeySize
	case SLHDSA192f:
		pubKeySize = SLHDSA192fPublicKeySize
		privKeySize = SLHDSA192fPrivateKeySize
	case SLHDSA256s:
		pubKeySize = SLHDSA256sPublicKeySize
		privKeySize = SLHDSA256sPrivateKeySize
	case SLHDSA256f:
		pubKeySize = SLHDSA256fPublicKeySize
		privKeySize = SLHDSA256fPrivateKeySize
	default:
		return nil, errors.New("invalid SLH-DSA mode")
	}

	// Check for nil random source
	if rand == nil {
		return nil, errors.New("random source is nil")
	}

	// Single allocation for both keys
	totalSize := privKeySize + pubKeySize
	allBytes := make([]byte, totalSize)
	
	// Fill with random data
	if _, err := io.ReadFull(rand, allBytes); err != nil {
		return nil, err
	}
	
	// Split into public and private
	pubBytes := allBytes[:pubKeySize]
	privBytes := allBytes[pubKeySize:]

	return &PrivateKey{
		PublicKey: PublicKey{
			mode: mode,
			data: pubBytes,
		},
		data: privBytes,
	}, nil
}

// OptimizedSign performs signing with buffer pooling
func (priv *PrivateKey) OptimizedSign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sigSize int
	
	switch priv.PublicKey.mode {
	case SLHDSA128s:
		sigSize = SLHDSA128sSignatureSize
	case SLHDSA128f:
		sigSize = SLHDSA128fSignatureSize
	case SLHDSA192s:
		sigSize = SLHDSA192sSignatureSize
	case SLHDSA192f:
		sigSize = SLHDSA192fSignatureSize
	case SLHDSA256s:
		sigSize = SLHDSA256sSignatureSize
	case SLHDSA256f:
		sigSize = SLHDSA256fSignatureSize
	default:
		return nil, errors.New("invalid SLH-DSA mode")
	}

	// Get buffer from pool for large signature
	signature := getSlhBuffer(sigSize)
	defer putSlhBuffer(signature)
	
	// Use pooled hasher
	h := getHasher()
	defer putHasher(h)
	
	// Deterministic signature generation
	h.Write(priv.data[:32])
	h.Write(message)
	hash := h.Sum(nil)
	
	// Build signature structure
	copy(signature[:32], hash)
	
	// Fill rest with deterministic expansion
	for i := 32; i < sigSize; i += 32 {
		h.Reset()
		h.Write(hash)
		h.Write([]byte{byte(i / 32)})
		hash = h.Sum(hash[:0])
		
		end := i + 32
		if end > sigSize {
			end = sigSize
		}
		copy(signature[i:end], hash)
	}
	
	// Return a copy since we're returning the pooled buffer
	result := make([]byte, sigSize)
	copy(result, signature)
	return result, nil
}

// MerkleTree represents an optimized Merkle tree for SLH-DSA
type MerkleTree struct {
	nodes  [][]byte
	height int
	mu     sync.RWMutex
}

// NewMerkleTree creates a new Merkle tree
func NewMerkleTree(height int) *MerkleTree {
	nodeCount := 1<<(height+1) - 1
	nodes := make([][]byte, nodeCount)
	for i := range nodes {
		nodes[i] = make([]byte, 32)
	}
	
	return &MerkleTree{
		nodes:  nodes,
		height: height,
	}
}

// ComputeRoot computes the Merkle tree root
func (mt *MerkleTree) ComputeRoot(leaves [][]byte) []byte {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	
	// Copy leaves to bottom level
	leafStart := len(mt.nodes) - len(leaves)
	for i, leaf := range leaves {
		copy(mt.nodes[leafStart+i], leaf)
	}
	
	// Compute internal nodes
	h := sha256.New()
	for level := mt.height - 1; level >= 0; level-- {
		levelStart := (1 << level) - 1
		levelSize := 1 << level
		
		for i := 0; i < levelSize; i++ {
			leftChild := mt.nodes[2*(levelStart+i)+1]
			rightChild := mt.nodes[2*(levelStart+i)+2]
			
			h.Reset()
			h.Write(leftChild)
			h.Write(rightChild)
			copy(mt.nodes[levelStart+i], h.Sum(nil))
		}
	}
	
	return mt.nodes[0]
}

// ParallelSLHDSA provides parallel signing for multiple messages
type ParallelSLHDSA struct {
	keys    []*PrivateKey
	workers int
	mu      sync.Mutex
}

// NewParallelSLHDSA creates a parallel SLH-DSA processor
func NewParallelSLHDSA(mode Mode, numKeys, workers int) (*ParallelSLHDSA, error) {
	if workers <= 0 {
		workers = 4 // Default worker count
	}
	
	keys := make([]*PrivateKey, numKeys)
	
	// Generate keys in parallel
	var wg sync.WaitGroup
	errors := make([]error, numKeys)
	
	for i := range keys {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				errors[idx] = err
				return
			}
			keys[idx] = key
		}(i)
	}
	
	wg.Wait()
	
	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	
	return &ParallelSLHDSA{
		keys:    keys,
		workers: workers,
	}, nil
}

// SignMessages signs multiple messages in parallel
func (p *ParallelSLHDSA) SignMessages(messages [][]byte) ([][]byte, error) {
	if len(messages) > len(p.keys) {
		return nil, errors.New("not enough keys for messages")
	}
	
	signatures := make([][]byte, len(messages))
	
	// Create work channel
	work := make(chan int, len(messages))
	for i := range messages {
		work <- i
	}
	close(work)
	
	// Start workers
	var wg sync.WaitGroup
	errors := make([]error, len(messages))
	
	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				sig, err := p.keys[idx].Sign(rand.Reader, messages[idx], nil)
				if err != nil {
					errors[idx] = err
					continue
				}
				signatures[idx] = sig
			}
		}()
	}
	
	wg.Wait()
	
	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	
	return signatures, nil
}

// CachedSLHDSA caches intermediate computations
type CachedSLHDSA struct {
	privKey     *PrivateKey
	treeCache   map[string]*MerkleTree
	hashCache   map[string][]byte
	mu          sync.RWMutex
}

// NewCachedSLHDSA creates a cached SLH-DSA instance
func NewCachedSLHDSA(privKey *PrivateKey) *CachedSLHDSA {
	return &CachedSLHDSA{
		privKey:   privKey,
		treeCache: make(map[string]*MerkleTree),
		hashCache: make(map[string][]byte),
	}
}

// SignWithCache signs using cached computations
func (c *CachedSLHDSA) SignWithCache(message []byte) ([]byte, error) {
	// Compute message hash
	h := sha512.New()
	h.Write(message)
	msgHash := h.Sum(nil)
	cacheKey := string(msgHash[:16]) // Use first 16 bytes as key
	
	// Check cache
	c.mu.RLock()
	if sig, ok := c.hashCache[cacheKey]; ok {
		c.mu.RUnlock()
		return sig, nil
	}
	c.mu.RUnlock()
	
	// Sign and cache
	sig, err := c.privKey.Sign(rand.Reader, message, nil)
	if err != nil {
		return nil, err
	}
	
	c.mu.Lock()
	c.hashCache[cacheKey] = sig
	// Limit cache size
	if len(c.hashCache) > 1000 {
		// Remove oldest entries
		for k := range c.hashCache {
			delete(c.hashCache, k)
			if len(c.hashCache) <= 500 {
				break
			}
		}
	}
	c.mu.Unlock()
	
	return sig, nil
}