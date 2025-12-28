// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// BLS (Boneh-Lynn-Shacham) signature precompiled contracts
// For aggregated signatures and threshold cryptography
// Uses gnark-crypto for real BLS12-381 operations

package precompile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// BLS precompile addresses
var (
	// BLS12-381 operations
	BLSVerifyAddress          = HexToAddress("0x0000000000000000000000000000000000000160")
	BLSAggregateVerifyAddress = HexToAddress("0x0000000000000000000000000000000000000161")
	BLSFastAggregateAddress   = HexToAddress("0x0000000000000000000000000000000000000162")

	// Threshold BLS operations
	BLSThresholdVerifyAddress  = HexToAddress("0x0000000000000000000000000000000000000163")
	BLSThresholdCombineAddress = HexToAddress("0x0000000000000000000000000000000000000164")

	// BLS key operations
	BLSPublicKeyAggregateAddress = HexToAddress("0x0000000000000000000000000000000000000165")
	BLSHashToPointAddress        = HexToAddress("0x0000000000000000000000000000000000000166")

	// Proof-of-possession
	BLSVerifyPoPAddress = HexToAddress("0x0000000000000000000000000000000000000167")
)

// Gas costs for BLS operations
const (
	blsVerifyGas             = 150000
	blsAggregateVerifyGas    = 200000
	blsFastAggregateGas      = 100000
	blsThresholdVerifyGas    = 250000
	blsThresholdCombineGas   = 180000
	blsPublicKeyAggregateGas = 50000
	blsHashToPointGas        = 80000
	blsVerifyPoPGas          = 150000

	// Per-item costs for aggregation
	blsPerSignatureGas = 30000
	blsPerPublicKeyGas = 10000

	// Point sizes
	g1Size = 48
	g2Size = 96

	// maxAggregateSigs caps the number of signatures in fast aggregate verify
	// to bound gas consumption and prevent abuse. 64 covers any reasonable
	// consensus committee size.
	maxAggregateSigs = 64
)

// BLSVerify implements single BLS signature verification
type BLSVerify struct{}

func (b *BLSVerify) RequiredGas(input []byte) uint64 {
	return blsVerifyGas
}

func (b *BLSVerify) Run(input []byte) ([]byte, error) {
	// Input: [96 bytes signature (G2)][48 bytes public key (G1)][message]
	if len(input) < g2Size+g1Size+1 {
		return nil, errors.New("input too short")
	}

	// Parse signature (G2 point)
	var sig bls12381.G2Affine
	if _, err := sig.SetBytes(input[:g2Size]); err != nil {
		return nil, errors.New("invalid signature point")
	}

	// Parse public key (G1 point)
	var pubKey bls12381.G1Affine
	if _, err := pubKey.SetBytes(input[g2Size : g2Size+g1Size]); err != nil {
		return nil, errors.New("invalid public key point")
	}

	// Parse message
	message := input[g2Size+g1Size:]

	// Hash message to G2
	msgPoint, err := bls12381.HashToG2(message, nil)
	if err != nil {
		return nil, errors.New("hash to curve failed")
	}

	// Get G1 generator
	_, _, g1Gen, _ := bls12381.Generators()

	// Verify: e(pubKey, H(m)) == e(G1, sig)
	// Equivalent to: e(pubKey, H(m)) * e(-G1, sig) == 1
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pubKey, negG1},
		[]bls12381.G2Affine{msgPoint, sig},
	)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}

	return result, nil
}

// BLSAggregateVerify verifies aggregate signature with different messages
type BLSAggregateVerify struct{}

func (b *BLSAggregateVerify) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return blsAggregateVerifyGas
	}
	numSigs := uint64(input[0])
	return blsAggregateVerifyGas + numSigs*blsPerSignatureGas
}

func (b *BLSAggregateVerify) Run(input []byte) ([]byte, error) {
	// Input: [1 byte num_sigs][aggregate_sig (96)][public_keys][messages]
	if len(input) < 1+g2Size {
		return nil, errors.New("input too short")
	}

	numSigs := int(input[0])
	if numSigs == 0 {
		return nil, errors.New("no signatures")
	}
	if numSigs > maxAggregateSigs {
		return nil, fmt.Errorf("too many signatures: %d > %d", numSigs, maxAggregateSigs)
	}

	// Parse aggregate signature
	var aggSig bls12381.G2Affine
	if _, err := aggSig.SetBytes(input[1 : 1+g2Size]); err != nil {
		return nil, errors.New("invalid aggregate signature")
	}

	// Parse public keys
	offset := 1 + g2Size
	pubKeys := make([]bls12381.G1Affine, numSigs)
	for i := 0; i < numSigs; i++ {
		if offset+g1Size > len(input) {
			return nil, errors.New("invalid public key")
		}
		if _, err := pubKeys[i].SetBytes(input[offset : offset+g1Size]); err != nil {
			return nil, errors.New("invalid public key point")
		}
		offset += g1Size
	}

	// Parse messages (length-prefixed)
	msgPoints := make([]bls12381.G2Affine, numSigs)
	for i := 0; i < numSigs; i++ {
		if offset+4 > len(input) {
			return nil, errors.New("invalid message encoding")
		}
		msgLen := int(binary.BigEndian.Uint32(input[offset : offset+4]))
		offset += 4

		if offset+msgLen > len(input) {
			return nil, errors.New("message too long")
		}

		msg := input[offset : offset+msgLen]
		offset += msgLen

		// Hash message to G2
		msgPoint, err := bls12381.HashToG2(msg, nil)
		if err != nil {
			return nil, errors.New("hash to curve failed")
		}
		msgPoints[i] = msgPoint
	}

	// Verify aggregate signature using multi-pairing
	// e(pk1, H(m1)) * e(pk2, H(m2)) * ... * e(pkn, H(mn)) == e(G1, aggSig)
	_, _, g1Gen, _ := bls12381.Generators()

	g1Points := make([]bls12381.G1Affine, numSigs+1)
	g2Points := make([]bls12381.G2Affine, numSigs+1)

	copy(g1Points[:numSigs], pubKeys)
	copy(g2Points[:numSigs], msgPoints)

	// Add negated generator paired with aggregate signature
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)
	g1Points[numSigs] = negG1
	g2Points[numSigs] = aggSig

	valid, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}

	return result, nil
}

// BLSFastAggregate verifies aggregate signature with same message.
//
// SECURITY: All public keys used in aggregation MUST have a verified
// proof-of-possession (BLSVerifyPoP) before being included. Without PoP,
// an attacker can perform a rogue key attack by choosing a crafted public
// key that cancels out honest participants' keys. Verify PoP on-chain
// before calling this precompile.
type BLSFastAggregate struct{}

func (b *BLSFastAggregate) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return blsFastAggregateGas
	}
	numKeys := uint64(input[0])
	return blsFastAggregateGas + numKeys*blsPerPublicKeyGas
}

func (b *BLSFastAggregate) Run(input []byte) ([]byte, error) {
	// Input: [1 byte num_keys][96 bytes aggregate_sig][public_keys][message]
	if len(input) < 1+g2Size {
		return nil, errors.New("input too short")
	}

	numKeys := int(input[0])
	if numKeys == 0 {
		return nil, errors.New("no public keys")
	}
	if numKeys > maxAggregateSigs {
		return nil, fmt.Errorf("too many keys: %d > %d", numKeys, maxAggregateSigs)
	}

	// Parse aggregate signature
	var aggSig bls12381.G2Affine
	if _, err := aggSig.SetBytes(input[1 : 1+g2Size]); err != nil {
		return nil, errors.New("invalid aggregate signature")
	}

	// Parse and aggregate public keys
	offset := 1 + g2Size
	var aggPubKey bls12381.G1Affine

	for i := 0; i < numKeys; i++ {
		if offset+g1Size > len(input) {
			return nil, errors.New("invalid public key")
		}
		var pk bls12381.G1Affine
		if _, err := pk.SetBytes(input[offset : offset+g1Size]); err != nil {
			return nil, errors.New("invalid public key point")
		}

		if i == 0 {
			aggPubKey = pk
		} else {
			aggPubKey.Add(&aggPubKey, &pk)
		}
		offset += g1Size
	}

	// Parse message (remainder)
	message := input[offset:]
	if len(message) == 0 {
		return nil, errors.New("empty message")
	}

	// Hash message to G2
	msgPoint, err := bls12381.HashToG2(message, nil)
	if err != nil {
		return nil, errors.New("hash to curve failed")
	}

	// Verify: e(aggPubKey, H(m)) == e(G1, aggSig)
	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{aggPubKey, negG1},
		[]bls12381.G2Affine{msgPoint, aggSig},
	)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}

	return result, nil
}

// BLSThresholdVerify verifies threshold signature
type BLSThresholdVerify struct{}

func (b *BLSThresholdVerify) RequiredGas(input []byte) uint64 {
	return blsThresholdVerifyGas
}

func (b *BLSThresholdVerify) Run(input []byte) ([]byte, error) {
	// Input: [1 byte threshold][1 byte num_shares][48 bytes group_pubkey][shares with indices][message]
	if len(input) < 2+g1Size+g2Size {
		return nil, errors.New("input too short")
	}

	threshold := int(input[0])
	numShares := int(input[1])

	if numShares < threshold {
		return nil, errors.New("insufficient shares for threshold")
	}

	// Parse group public key
	var groupPubKey bls12381.G1Affine
	if _, err := groupPubKey.SetBytes(input[2 : 2+g1Size]); err != nil {
		return nil, errors.New("invalid group public key")
	}

	// Parse signature shares and their indices
	offset := 2 + g1Size
	shares := make([]bls12381.G2Affine, numShares)
	indices := make([]uint64, numShares)

	for i := 0; i < numShares; i++ {
		if offset+8+g2Size > len(input) {
			return nil, errors.New("invalid share")
		}

		// Read index (8 bytes)
		indices[i] = binary.BigEndian.Uint64(input[offset : offset+8])
		offset += 8

		// Read share (G2 point)
		if _, err := shares[i].SetBytes(input[offset : offset+g2Size]); err != nil {
			return nil, errors.New("invalid signature share")
		}
		offset += g2Size
	}

	// Parse message
	message := input[offset:]
	if len(message) == 0 {
		return nil, errors.New("empty message")
	}

	// Combine shares using Lagrange interpolation
	combinedSig := combineThresholdShares(shares, indices, threshold)

	// Hash message to G2
	msgPoint, err := bls12381.HashToG2(message, nil)
	if err != nil {
		return nil, errors.New("hash to curve failed")
	}

	// Verify combined signature
	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{groupPubKey, negG1},
		[]bls12381.G2Affine{msgPoint, combinedSig},
	)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}

	return result, nil
}

// combineThresholdShares combines threshold signature shares using Lagrange interpolation
func combineThresholdShares(shares []bls12381.G2Affine, indices []uint64, threshold int) bls12381.G2Affine {
	var combined bls12381.G2Affine

	for i := 0; i < threshold; i++ {
		// Compute Lagrange coefficient
		lambda := computeLagrangeCoeff(indices, i, threshold)

		// Multiply share by lambda
		var scaledShare bls12381.G2Affine
		scaledShare.ScalarMultiplication(&shares[i], lambda.BigInt(new(big.Int)))

		if i == 0 {
			combined = scaledShare
		} else {
			combined.Add(&combined, &scaledShare)
		}
	}

	return combined
}

// computeLagrangeCoeff computes Lagrange coefficient for party at position i
func computeLagrangeCoeff(indices []uint64, i, t int) fr.Element {
	var lambda fr.Element
	lambda.SetOne()

	for j := 0; j < t; j++ {
		if i == j {
			continue
		}

		// lambda *= (0 - x_j) / (x_i - x_j)
		// Since we're evaluating at 0: lambda *= -x_j / (x_i - x_j)
		var xi, xj, num, denom fr.Element
		xi.SetUint64(indices[i] + 1) // 1-indexed for proper interpolation
		xj.SetUint64(indices[j] + 1)

		num.Neg(&xj)        // -x_j
		denom.Sub(&xi, &xj) // x_i - x_j
		denom.Inverse(&denom)

		num.Mul(&num, &denom)
		lambda.Mul(&lambda, &num)
	}

	return lambda
}

// BLSThresholdCombine combines threshold signature shares
type BLSThresholdCombine struct{}

func (b *BLSThresholdCombine) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return blsThresholdCombineGas
	}
	numShares := uint64(input[0])
	return blsThresholdCombineGas + numShares*blsPerSignatureGas
}

func (b *BLSThresholdCombine) Run(input []byte) ([]byte, error) {
	// Input: [1 byte num_shares][shares with indices...]
	if len(input) < 2 {
		return nil, errors.New("input too short")
	}

	numShares := int(input[0])
	threshold := int(input[1])

	if numShares < threshold {
		return nil, errors.New("insufficient shares")
	}

	// Parse shares and indices
	offset := 2
	shares := make([]bls12381.G2Affine, numShares)
	indices := make([]uint64, numShares)

	for i := 0; i < numShares; i++ {
		if offset+8+g2Size > len(input) {
			return nil, errors.New("invalid share encoding")
		}

		// Read index
		indices[i] = binary.BigEndian.Uint64(input[offset : offset+8])
		offset += 8

		// Read share
		if _, err := shares[i].SetBytes(input[offset : offset+g2Size]); err != nil {
			return nil, errors.New("invalid signature share point")
		}
		offset += g2Size
	}

	// Combine using Lagrange interpolation
	combined := combineThresholdShares(shares, indices, threshold)

	// Return combined signature (96 bytes)
	bytes := combined.Bytes()
	return bytes[:], nil
}

// BLSPublicKeyAggregate aggregates multiple BLS public keys
type BLSPublicKeyAggregate struct{}

func (b *BLSPublicKeyAggregate) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return blsPublicKeyAggregateGas
	}
	numKeys := uint64(input[0])
	return blsPublicKeyAggregateGas + numKeys*blsPerPublicKeyGas
}

func (b *BLSPublicKeyAggregate) Run(input []byte) ([]byte, error) {
	// Input: [1 byte num_keys][public_keys...]
	if len(input) < 1 {
		return nil, errors.New("input too short")
	}

	numKeys := int(input[0])
	expectedSize := 1 + numKeys*g1Size

	if len(input) < expectedSize {
		return nil, errors.New("invalid input size")
	}

	if numKeys == 0 {
		return nil, errors.New("no public keys")
	}

	// Parse and aggregate public keys using G1 point addition
	var aggregatedKey bls12381.G1Affine

	for i := 0; i < numKeys; i++ {
		offset := 1 + i*g1Size
		var pk bls12381.G1Affine
		if _, err := pk.SetBytes(input[offset : offset+g1Size]); err != nil {
			return nil, errors.New("invalid public key point")
		}

		if i == 0 {
			aggregatedKey = pk
		} else {
			aggregatedKey.Add(&aggregatedKey, &pk)
		}
	}

	bytes := aggregatedKey.Bytes()
	return bytes[:], nil
}

// BLSHashToPoint hashes message to BLS12-381 G2 point
type BLSHashToPoint struct{}

func (b *BLSHashToPoint) RequiredGas(input []byte) uint64 {
	return blsHashToPointGas
}

func (b *BLSHashToPoint) Run(input []byte) ([]byte, error) {
	// Input: message to hash
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}

	// Use gnark-crypto's hash-to-curve implementation
	g2Point, err := bls12381.HashToG2(input, nil)
	if err != nil {
		return nil, errors.New("hash to curve failed")
	}

	bytes := g2Point.Bytes()
	return bytes[:], nil
}

// BLSVerifyPoP verifies proof-of-possession for a BLS public key.
// A PoP is a BLS signature over the serialized public key itself, proving the
// holder knows the corresponding secret key. This MUST be verified before any
// key is used in aggregation (BLSFastAggregate, BLSPublicKeyAggregate) to
// prevent rogue key attacks.
type BLSVerifyPoP struct{}

func (b *BLSVerifyPoP) RequiredGas(input []byte) uint64 {
	return blsVerifyPoPGas
}

func (b *BLSVerifyPoP) Run(input []byte) ([]byte, error) {
	// Input: [48 bytes public_key (G1)][96 bytes pop_signature (G2)]
	if len(input) < g1Size+g2Size {
		return nil, fmt.Errorf("input too short: need %d bytes, got %d", g1Size+g2Size, len(input))
	}

	pubKeyBytes := input[:g1Size]
	popBytes := input[g1Size : g1Size+g2Size]

	// Parse public key (G1 point)
	var pubKey bls12381.G1Affine
	if _, err := pubKey.SetBytes(pubKeyBytes); err != nil {
		return nil, errors.New("invalid public key point")
	}

	// Parse PoP signature (G2 point)
	var popSig bls12381.G2Affine
	if _, err := popSig.SetBytes(popBytes); err != nil {
		return nil, errors.New("invalid PoP signature point")
	}

	// PoP = Sign(sk, pubkey_bytes). Verify by checking the BLS signature
	// over the raw public key bytes using that same public key.
	msgPoint, err := bls12381.HashToG2(pubKeyBytes, nil)
	if err != nil {
		return nil, errors.New("hash to curve failed")
	}

	// Verify: e(pubKey, H(pubKeyBytes)) == e(G1, popSig)
	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pubKey, negG1},
		[]bls12381.G2Affine{msgPoint, popSig},
	)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 0x01
	}
	return result, nil
}

// RegisterBLS registers all BLS precompiles
func RegisterBLS(registry *Registry) {
	registry.Register(BLSVerifyAddress, &BLSVerify{})
	registry.Register(BLSAggregateVerifyAddress, &BLSAggregateVerify{})
	registry.Register(BLSFastAggregateAddress, &BLSFastAggregate{})
	registry.Register(BLSThresholdVerifyAddress, &BLSThresholdVerify{})
	registry.Register(BLSThresholdCombineAddress, &BLSThresholdCombine{})
	registry.Register(BLSPublicKeyAggregateAddress, &BLSPublicKeyAggregate{})
	registry.Register(BLSHashToPointAddress, &BLSHashToPoint{})
	registry.Register(BLSVerifyPoPAddress, &BLSVerifyPoP{})
}

func init() {
	// Auto-register BLS precompiles on package load
	RegisterBLS(PostQuantumRegistry)
}
