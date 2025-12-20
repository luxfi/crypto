// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// LSAGSignature implements linkable ring signatures using secp256k1.
// Based on the Linkable Spontaneous Anonymous Group signature scheme.
type LSAGSignature struct {
	keyImage []byte   // 33 bytes compressed point
	c        []byte   // 32 bytes - initial challenge c[0]
	s        [][]byte // n * 32 bytes - response scalars
}

// Scheme returns LSAG.
func (sig *LSAGSignature) Scheme() Scheme {
	return LSAG
}

// Bytes serializes the signature.
func (sig *LSAGSignature) Bytes() []byte {
	n := len(sig.s)
	data := make([]byte, 33+32+4+n*32)

	copy(data[0:33], sig.keyImage)
	copy(data[33:65], sig.c)
	binary.BigEndian.PutUint32(data[65:69], uint32(n))

	offset := 69
	for _, si := range sig.s {
		copy(data[offset:offset+32], si)
		offset += 32
	}

	return data
}

// KeyImage returns the key image for linkability.
func (sig *LSAGSignature) KeyImage() []byte {
	return sig.keyImage
}

// RingSize returns the number of public keys in the ring.
func (sig *LSAGSignature) RingSize() int {
	return len(sig.s)
}

// Verify verifies the signature against the message and ring.
func (sig *LSAGSignature) Verify(message []byte, ring [][]byte) bool {
	n := len(ring)
	if n != len(sig.s) || n < 2 {
		return false
	}

	// Parse key image
	keyImage, err := secp256k1.ParsePubKey(sig.keyImage)
	if err != nil {
		return false
	}

	// Parse public keys
	pubKeys := make([]*secp256k1.PublicKey, n)
	for i, pkBytes := range ring {
		pk, err := secp256k1.ParsePubKey(pkBytes)
		if err != nil {
			return false
		}
		pubKeys[i] = pk
	}

	// Compute hash points for each ring member: H_p(P_i)
	hashPoints := make([]*secp256k1.PublicKey, n)
	for i := 0; i < n; i++ {
		hashPoints[i] = hashToPoint([][]byte{ring[i]})
	}

	// Reconstruct challenge chain
	c := new(big.Int).SetBytes(sig.c)
	curveN := secp256k1.S256().N

	for i := 0; i < n; i++ {
		si := new(big.Int).SetBytes(sig.s[i])

		// L_i = s_i * G + c_i * P_i
		sG := scalarBaseMult(si)
		cP := scalarMult(c, pubKeys[i])
		L := pointAdd(sG, cP)

		// R_i = s_i * H_p(P_i) + c_i * I
		sH := scalarMult(si, hashPoints[i])
		cI := scalarMult(c, keyImage)
		R := pointAdd(sH, cI)

		// c_{i+1} = H(m, L_i, R_i)
		c = hashToScalar(message, L, R, curveN)
	}

	// Check c_n == c_0
	c0 := new(big.Int).SetBytes(sig.c)
	return c.Cmp(c0) == 0
}

// ParseLSAGSignature parses an LSAG signature from bytes.
func ParseLSAGSignature(data []byte) (*LSAGSignature, error) {
	if len(data) < 69 {
		return nil, errors.New("signature too short")
	}

	sig := &LSAGSignature{
		keyImage: make([]byte, 33),
		c:        make([]byte, 32),
	}

	copy(sig.keyImage, data[0:33])
	copy(sig.c, data[33:65])

	n := int(binary.BigEndian.Uint32(data[65:69]))
	if len(data) != 69+n*32 {
		return nil, errors.New("invalid signature length")
	}

	sig.s = make([][]byte, n)
	offset := 69
	for i := 0; i < n; i++ {
		sig.s[i] = make([]byte, 32)
		copy(sig.s[i], data[offset:offset+32])
		offset += 32
	}

	return sig, nil
}

// LSAGSigner creates LSAG ring signatures.
type LSAGSigner struct {
	privateKey *secp256k1.PrivateKey
	publicKey  *secp256k1.PublicKey
	keyImage   *secp256k1.PublicKey
}

// NewLSAGSigner creates a new LSAG signer with a random private key.
func NewLSAGSigner(reader io.Reader) (*LSAGSigner, error) {
	if reader == nil {
		reader = rand.Reader
	}
	privKey, err := secp256k1.GeneratePrivateKeyFromRand(reader)
	if err != nil {
		return nil, err
	}
	return newLSAGSignerFromKey(privKey)
}

// NewLSAGSignerFromPrivateKey creates an LSAG signer from an existing private key.
func NewLSAGSignerFromPrivateKey(privateKey []byte) (*LSAGSigner, error) {
	if len(privateKey) != 32 {
		return nil, ErrInvalidPrivateKey
	}
	privKey := secp256k1.PrivKeyFromBytes(privateKey)
	return newLSAGSignerFromKey(privKey)
}

func newLSAGSignerFromKey(privKey *secp256k1.PrivateKey) (*LSAGSigner, error) {
	pubKey := privKey.PubKey()

	// Compute key image: I = x * H_p(P)
	pubKeyBytes := pubKey.SerializeCompressed()
	Hp := hashToPoint([][]byte{pubKeyBytes})
	x := new(big.Int).SetBytes(privKey.Serialize())
	keyImage := scalarMult(x, Hp)

	return &LSAGSigner{
		privateKey: privKey,
		publicKey:  pubKey,
		keyImage:   keyImage,
	}, nil
}

// Scheme returns LSAG.
func (s *LSAGSigner) Scheme() Scheme {
	return LSAG
}

// PublicKey returns the signer's compressed public key.
func (s *LSAGSigner) PublicKey() []byte {
	return s.publicKey.SerializeCompressed()
}

// KeyImage returns the key image.
func (s *LSAGSigner) KeyImage() []byte {
	return s.keyImage.SerializeCompressed()
}

// Sign creates a ring signature for the message.
func (signer *LSAGSigner) Sign(message []byte, ring [][]byte, signerIndex int) (RingSignature, error) {
	n := len(ring)
	if n < 2 {
		return nil, ErrInvalidRingSize
	}
	if signerIndex < 0 || signerIndex >= n {
		return nil, ErrInvalidSignerIndex
	}

	// Parse ring public keys
	pubKeys := make([]*secp256k1.PublicKey, n)
	for i, pkBytes := range ring {
		pk, err := secp256k1.ParsePubKey(pkBytes)
		if err != nil {
			return nil, ErrInvalidPublicKey
		}
		pubKeys[i] = pk
	}

	// Verify signer's key is at the specified index
	if !pubKeys[signerIndex].IsEqual(signer.publicKey) {
		return nil, errors.New("signer public key not at specified index")
	}

	curveN := secp256k1.S256().N

	// Compute hash points for each ring member: H_p(P_i)
	hashPoints := make([]*secp256k1.PublicKey, n)
	for i := 0; i < n; i++ {
		hashPoints[i] = hashToPoint([][]byte{ring[i]})
	}

	// Generate random alpha
	alpha := randomScalar(curveN)

	// Compute L_π = α*G and R_π = α*H_p(P_π)
	Lpi := scalarBaseMult(alpha)
	Rpi := scalarMult(alpha, hashPoints[signerIndex])

	// Initialize challenges and responses
	c := make([]*big.Int, n)
	s := make([]*big.Int, n)

	// c_{π+1} = H(m, L_π, R_π)
	nextIdx := (signerIndex + 1) % n
	c[nextIdx] = hashToScalar(message, Lpi, Rpi, curveN)

	// Generate random s values and compute challenges for non-signer indices
	for i := 1; i < n; i++ {
		idx := (signerIndex + i) % n
		nextIdx := (idx + 1) % n

		// Random response for this index
		s[idx] = randomScalar(curveN)

		// L = s*G + c*P
		sG := scalarBaseMult(s[idx])
		cP := scalarMult(c[idx], pubKeys[idx])
		L := pointAdd(sG, cP)

		// R = s*H_p(P_idx) + c*I
		sH := scalarMult(s[idx], hashPoints[idx])
		cI := scalarMult(c[idx], signer.keyImage)
		R := pointAdd(sH, cI)

		// c_{next} = H(m, L, R)
		c[nextIdx] = hashToScalar(message, L, R, curveN)
	}

	// Compute s_π = α - c_π * x (mod n)
	x := new(big.Int).SetBytes(signer.privateKey.Serialize())
	s[signerIndex] = new(big.Int).Mul(c[signerIndex], x)
	s[signerIndex].Sub(alpha, s[signerIndex])
	s[signerIndex].Mod(s[signerIndex], curveN)

	// Build signature
	sig := &LSAGSignature{
		keyImage: signer.keyImage.SerializeCompressed(),
		c:        padTo32(c[0].Bytes()),
		s:        make([][]byte, n),
	}
	for i := 0; i < n; i++ {
		sig.s[i] = padTo32(s[i].Bytes())
	}

	return sig, nil
}

// Helper functions

func randomScalar(n *big.Int) *big.Int {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			continue
		}
		k := new(big.Int).SetBytes(b)
		k.Mod(k, n)
		if k.Sign() > 0 {
			return k
		}
	}
}

func hashToPoint(ring [][]byte) *secp256k1.PublicKey {
	// Hash ring to a curve point using try-and-increment
	h := sha256.New()
	for _, pk := range ring {
		h.Write(pk)
	}
	hash := h.Sum(nil)

	for i := 0; i < 256; i++ {
		tryHash := sha256.Sum256(append(hash, byte(i)))
		compressed := make([]byte, 33)
		compressed[0] = 0x02 + (tryHash[0] & 0x01)
		copy(compressed[1:], tryHash[:32])

		pk, err := secp256k1.ParsePubKey(compressed)
		if err == nil {
			return pk
		}
	}

	// Fallback: multiply generator by hash
	scalar := new(big.Int).SetBytes(hash)
	scalar.Mod(scalar, secp256k1.S256().N)
	if scalar.Sign() == 0 {
		scalar.SetInt64(1)
	}
	return scalarBaseMult(scalar)
}

func hashToScalar(message []byte, L, R *secp256k1.PublicKey, n *big.Int) *big.Int {
	h := sha256.New()
	h.Write(message)
	h.Write(L.SerializeCompressed())
	h.Write(R.SerializeCompressed())
	hash := h.Sum(nil)

	c := new(big.Int).SetBytes(hash)
	c.Mod(c, n)
	if c.Sign() == 0 {
		c.SetInt64(1)
	}
	return c
}

func scalarBaseMult(k *big.Int) *secp256k1.PublicKey {
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(padTo32(k.Bytes()))

	var point secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&scalar, &point)
	point.ToAffine()

	return secp256k1.NewPublicKey(&point.X, &point.Y)
}

func scalarMult(k *big.Int, point *secp256k1.PublicKey) *secp256k1.PublicKey {
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(padTo32(k.Bytes()))

	var jp secp256k1.JacobianPoint
	point.AsJacobian(&jp)

	var result secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&scalar, &jp, &result)
	result.ToAffine()

	return secp256k1.NewPublicKey(&result.X, &result.Y)
}

func pointAdd(p1, p2 *secp256k1.PublicKey) *secp256k1.PublicKey {
	var jp1, jp2 secp256k1.JacobianPoint
	p1.AsJacobian(&jp1)
	p2.AsJacobian(&jp2)

	var result secp256k1.JacobianPoint
	secp256k1.AddNonConst(&jp1, &jp2, &result)
	result.ToAffine()

	return secp256k1.NewPublicKey(&result.X, &result.Y)
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
