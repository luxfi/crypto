//go:build !cgo || !gpu

// Package gpu provides GPU-accelerated cryptographic operations.
// This file provides pure Go fallback implementations when CGO is disabled or the gpu build tag is not set.
// Uses gnark-crypto for BLS12-381, cloudflare/circl for ML-DSA.
package gpu

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

// Error definitions
var (
	ErrInvalidKey       = errors.New("invalid key")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrCGORequired      = errors.New("CGO required for this operation")
)

// Pure Go fallback - no GPU acceleration
func GPUAvailable() bool { return false }
func GetBackend() string { return "CPU (pure Go)" }
func ClearCache()        {}

// =============================================================================
// BLS12-381 Pure Go Implementation (using gnark-crypto)
// =============================================================================

var blsDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

func BLSKeygen(seed []byte) ([]byte, error) {
	var scalar fr.Element
	if seed != nil && len(seed) >= 32 {
		scalar.SetBytes(seed[:32])
	} else {
		_, err := scalar.SetRandom()
		if err != nil {
			return nil, err
		}
	}
	return scalar.Marshal(), nil
}

func BLSSecretKeyToPublicKey(sk []byte) ([]byte, error) {
	if len(sk) != BLSSecretKeySize {
		return nil, ErrInvalidKey
	}

	var scalar fr.Element
	if err := scalar.SetBytesCanonical(sk); err != nil {
		return nil, err
	}

	_, _, g1Gen, _ := bls12381.Generators()
	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1Gen, scalar.BigInt(new(big.Int)))

	return pk.Marshal(), nil
}

func BLSSign(sk, msg []byte) ([]byte, error) {
	if len(sk) != BLSSecretKeySize || len(msg) != BLSMessageSize {
		return nil, ErrInvalidKey
	}

	var scalar fr.Element
	if err := scalar.SetBytesCanonical(sk); err != nil {
		return nil, err
	}

	// Hash to G2
	msgPoint, err := bls12381.HashToG2(msg, blsDST)
	if err != nil {
		return nil, err
	}

	// Multiply by secret key
	var sig bls12381.G2Affine
	sig.ScalarMultiplication(&msgPoint, scalar.BigInt(new(big.Int)))

	return sig.Marshal(), nil
}

func BLSVerify(sig, pk, msg []byte) bool {
	if len(sig) != BLSSignatureSize || len(pk) != BLSPublicKeySize || len(msg) != BLSMessageSize {
		return false
	}

	var sigPoint bls12381.G2Affine
	if err := sigPoint.Unmarshal(sig); err != nil {
		return false
	}

	var pkPoint bls12381.G1Affine
	if err := pkPoint.Unmarshal(pk); err != nil {
		return false
	}

	msgPoint, err := bls12381.HashToG2(msg, blsDST)
	if err != nil {
		return false
	}

	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	result, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pkPoint, negG1},
		[]bls12381.G2Affine{msgPoint, sigPoint},
	)

	return err == nil && result
}

func BLSAggregateSignatures(sigs [][]byte) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, errors.New("empty signatures")
	}

	var result bls12381.G2Jac
	for i, sigBytes := range sigs {
		if len(sigBytes) != BLSSignatureSize {
			return nil, ErrInvalidSignature
		}
		var sig bls12381.G2Affine
		if err := sig.Unmarshal(sigBytes); err != nil {
			return nil, err
		}
		if i == 0 {
			result.FromAffine(&sig)
		} else {
			var jac bls12381.G2Jac
			jac.FromAffine(&sig)
			result.AddAssign(&jac)
		}
	}

	var resultAffine bls12381.G2Affine
	resultAffine.FromJacobian(&result)
	return resultAffine.Marshal(), nil
}

func BLSAggregatePublicKeys(pks [][]byte) ([]byte, error) {
	if len(pks) == 0 {
		return nil, errors.New("empty public keys")
	}

	var result bls12381.G1Jac
	for i, pkBytes := range pks {
		if len(pkBytes) != BLSPublicKeySize {
			return nil, ErrInvalidKey
		}
		var pk bls12381.G1Affine
		if err := pk.Unmarshal(pkBytes); err != nil {
			return nil, err
		}
		if i == 0 {
			result.FromAffine(&pk)
		} else {
			var jac bls12381.G1Jac
			jac.FromAffine(&pk)
			result.AddAssign(&jac)
		}
	}

	var resultAffine bls12381.G1Affine
	resultAffine.FromJacobian(&result)
	return resultAffine.Marshal(), nil
}

func BLSVerifyAggregated(aggSig, aggPK, msg []byte) bool {
	return BLSVerify(aggSig, aggPK, msg)
}

func BLSBatchVerify(sigs, pks, msgs [][]byte) ([]bool, error) {
	if len(sigs) != len(pks) || len(pks) != len(msgs) {
		return nil, errors.New("mismatched lengths")
	}

	results := make([]bool, len(sigs))
	var wg sync.WaitGroup

	for i := range sigs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = BLSVerify(sigs[idx], pks[idx], msgs[idx])
		}(i)
	}

	wg.Wait()
	return results, nil
}

func BLSBatchSign(sks, msgs [][]byte) ([][]byte, error) {
	if len(sks) != len(msgs) {
		return nil, errors.New("mismatched lengths")
	}

	results := make([][]byte, len(sks))
	errs := make([]error, len(sks))
	var wg sync.WaitGroup

	for i := range sks {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = BLSSign(sks[idx], msgs[idx])
		}(i)
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

// =============================================================================
// ML-DSA (Dilithium) Pure Go Implementation (using cloudflare/circl)
// =============================================================================

func MLDSAKeygen(seed []byte) (pk, sk []byte, err error) {
	var pubKey *mldsa65.PublicKey
	var privKey *mldsa65.PrivateKey

	if seed != nil && len(seed) >= 32 {
		// Deterministic keygen from seed - copy to fixed size array
		var seedArr [32]byte
		copy(seedArr[:], seed[:32])
		pubKey, privKey = mldsa65.NewKeyFromSeed(&seedArr)
	} else {
		// Random keygen
		pubKey, privKey, err = mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	}

	pkBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pkBytes, skBytes, nil
}

func MLDSASign(sk, msg []byte) ([]byte, error) {
	var privKey mldsa65.PrivateKey
	if err := privKey.UnmarshalBinary(sk); err != nil {
		return nil, err
	}

	// SignTo writes to a provided buffer, returns signature
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&privKey, msg, nil, false, sig)
	return sig, nil
}

func MLDSAVerify(sig, msg, pk []byte) bool {
	var pubKey mldsa65.PublicKey
	if err := pubKey.UnmarshalBinary(pk); err != nil {
		return false
	}

	return mldsa65.Verify(&pubKey, msg, nil, sig)
}

func MLDSABatchVerify(sigs, msgs [][]byte, pks [][]byte) ([]bool, error) {
	if len(sigs) != len(msgs) || len(msgs) != len(pks) {
		return nil, errors.New("mismatched lengths")
	}

	results := make([]bool, len(sigs))
	var wg sync.WaitGroup

	for i := range sigs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = MLDSAVerify(sigs[idx], msgs[idx], pks[idx])
		}(i)
	}

	wg.Wait()
	return results, nil
}

// =============================================================================
// Threshold Signatures Pure Go Implementation
// =============================================================================

type ThresholdContext struct {
	t, n uint32
}

func NewThresholdContext(t, n uint32) (*ThresholdContext, error) {
	if t > n || t == 0 {
		return nil, errors.New("invalid threshold parameters")
	}
	return &ThresholdContext{t: t, n: n}, nil
}

func (tc *ThresholdContext) Close() {}

func (tc *ThresholdContext) Keygen(seed []byte) (shares [][]byte, pk []byte, err error) {
	// Simple Shamir Secret Sharing for BLS keys
	masterSK, err := BLSKeygen(seed)
	if err != nil {
		return nil, nil, err
	}

	pk, err = BLSSecretKeyToPublicKey(masterSK)
	if err != nil {
		return nil, nil, err
	}

	// Generate polynomial coefficients
	var coeffs []fr.Element
	coeffs = make([]fr.Element, tc.t)
	coeffs[0].SetBytes(masterSK)

	for i := uint32(1); i < tc.t; i++ {
		if _, err := coeffs[i].SetRandom(); err != nil {
			return nil, nil, err
		}
	}

	// Evaluate polynomial at points 1..n
	shares = make([][]byte, tc.n)
	for i := uint32(0); i < tc.n; i++ {
		var x, y fr.Element
		x.SetUint64(uint64(i + 1))

		// Horner's method
		y.Set(&coeffs[tc.t-1])
		for j := int(tc.t) - 2; j >= 0; j-- {
			y.Mul(&y, &x)
			y.Add(&y, &coeffs[j])
		}

		shares[i] = y.Marshal()
	}

	return shares, pk, nil
}

func (tc *ThresholdContext) PartialSign(shareIndex uint32, share, msg []byte) ([]byte, error) {
	return BLSSign(share, msg)
}

func (tc *ThresholdContext) Combine(partialSigs [][]byte, indices []uint32) ([]byte, error) {
	if len(partialSigs) < int(tc.t) {
		return nil, errors.New("insufficient shares")
	}

	// Lagrange interpolation coefficients
	lagrange := make([]fr.Element, len(indices))
	for i := range indices {
		var num, den fr.Element
		num.SetOne()
		den.SetOne()

		var xi fr.Element
		xi.SetUint64(uint64(indices[i] + 1))

		for j := range indices {
			if i == j {
				continue
			}
			var xj fr.Element
			xj.SetUint64(uint64(indices[j] + 1))

			// num *= xj
			num.Mul(&num, &xj)

			// den *= (xj - xi)
			var diff fr.Element
			diff.Sub(&xj, &xi)
			den.Mul(&den, &diff)
		}

		lagrange[i].Div(&num, &den)
	}

	// Combine signatures: sum of sig_i * lagrange_i
	var result bls12381.G2Jac

	for i, sigBytes := range partialSigs {
		var sig bls12381.G2Affine
		if err := sig.Unmarshal(sigBytes); err != nil {
			return nil, err
		}

		var scaled bls12381.G2Affine
		scaled.ScalarMultiplication(&sig, lagrange[i].BigInt(new(big.Int)))

		if i == 0 {
			result.FromAffine(&scaled)
		} else {
			var jac bls12381.G2Jac
			jac.FromAffine(&scaled)
			result.AddAssign(&jac)
		}
	}

	var resultAffine bls12381.G2Affine
	resultAffine.FromJacobian(&result)
	return resultAffine.Marshal(), nil
}

func (tc *ThresholdContext) Verify(sig, pk, msg []byte) bool {
	return BLSVerify(sig, pk, msg)
}

// =============================================================================
// Hash Functions Pure Go Implementation
// =============================================================================

func SHA3_256(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

func SHA3_512(data []byte) []byte {
	h := sha3.New512()
	h.Write(data)
	return h.Sum(nil)
}

func BLAKE3(data []byte) []byte {
	h := blake3.New()
	h.Write(data)
	return h.Sum(nil)
}

func BatchHash(inputs [][]byte, hashType int) ([][]byte, error) {
	results := make([][]byte, len(inputs))
	var wg sync.WaitGroup

	for i := range inputs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			switch hashType {
			case 0:
				results[idx] = SHA3_256(inputs[idx])
			case 1:
				results[idx] = SHA3_512(inputs[idx])
			case 2:
				results[idx] = BLAKE3(inputs[idx])
			}
		}(i)
	}

	wg.Wait()
	return results, nil
}

// =============================================================================
// Consensus Helpers
// =============================================================================

func ConsensusVerifyBlock(blsSigs, blsPKs [][]byte, thresholdSig, thresholdPK, blockHash []byte) bool {
	// Verify all BLS signatures
	for i := range blsSigs {
		if !BLSVerify(blsSigs[i], blsPKs[i], blockHash) {
			return false
		}
	}

	// Verify threshold signature
	if len(thresholdSig) > 0 && len(thresholdPK) > 0 {
		if !BLSVerify(thresholdSig, thresholdPK, blockHash) {
			return false
		}
	}

	return true
}
