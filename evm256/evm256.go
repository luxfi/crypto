// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evm256

import (
	"errors"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// PointSize is the size of an encoded G1 point on the EVM ABI: 64 bytes
// (X || Y, big-endian, 32 bytes each).
const PointSize = 64

// PairingPairSize is the size of one (G1, G2) pair on the EVM ABI:
// 64 + 128 = 192 bytes.
const PairingPairSize = 192

var (
	ErrShortInput      = errors.New("evm256: input too short")
	ErrInvalidPoint    = errors.New("evm256: point not on curve")
	ErrInvalidPairings = errors.New("evm256: pairing input length not a multiple of 192")
)

// Add implements the bn256Add precompile (EIP-196): adds two G1 points
// encoded as 64-byte X||Y blobs and returns the sum, also as 64 bytes.
//
// Per EIP-196, missing input bytes are treated as zero; bytes past
// 2*PointSize are ignored.
func Add(input []byte) ([]byte, error) {
	a, err := decodeG1(zeroPad(input, 0, PointSize))
	if err != nil {
		return nil, err
	}
	b, err := decodeG1(zeroPad(input, PointSize, PointSize))
	if err != nil {
		return nil, err
	}
	var sum bn254.G1Jac
	sum.FromAffine(&a).AddMixed(&b)
	var out bn254.G1Affine
	out.FromJacobian(&sum)
	return encodeG1(out), nil
}

// ScalarMul implements the bn256ScalarMul precompile (EIP-196): multiplies
// G1 point P by scalar k and returns the resulting point. P is 64 bytes,
// k is 32 bytes; total input 96 bytes.
func ScalarMul(input []byte) ([]byte, error) {
	p, err := decodeG1(zeroPad(input, 0, PointSize))
	if err != nil {
		return nil, err
	}
	scalar := new(big.Int).SetBytes(zeroPad(input, PointSize, 32))
	var pJ bn254.G1Jac
	pJ.FromAffine(&p)
	pJ.ScalarMultiplication(&pJ, scalar)
	var out bn254.G1Affine
	out.FromJacobian(&pJ)
	return encodeG1(out), nil
}

// PairingCheck implements the bn256Pairing precompile (EIP-197). The input
// is a flat list of (G1, G2) pairs. Returns 0x...01 if the multi-pairing
// equals 1 in GT, else 0x...00 (32 bytes total).
//
// Empty input is well-defined per the spec and returns 0x..01.
func PairingCheck(input []byte) ([]byte, error) {
	if len(input)%PairingPairSize != 0 {
		return nil, ErrInvalidPairings
	}
	out := make([]byte, 32)
	n := len(input) / PairingPairSize
	if n == 0 {
		out[31] = 1
		return out, nil
	}
	a := make([]bn254.G1Affine, n)
	b := make([]bn254.G2Affine, n)
	for i := 0; i < n; i++ {
		off := i * PairingPairSize
		var err error
		a[i], err = decodeG1(input[off : off+PointSize])
		if err != nil {
			return nil, err
		}
		b[i], err = decodeG2(input[off+PointSize : off+PairingPairSize])
		if err != nil {
			return nil, err
		}
	}
	ok, err := bn254.PairingCheck(a, b)
	if err != nil {
		return nil, err
	}
	if ok {
		out[31] = 1
	}
	return out, nil
}

// zeroPad returns input[off:off+n] zero-padded if shorter than off+n.
func zeroPad(input []byte, off, n int) []byte {
	out := make([]byte, n)
	if off >= len(input) {
		return out
	}
	end := off + n
	if end > len(input) {
		end = len(input)
	}
	copy(out, input[off:end])
	return out
}

func decodeG1(buf []byte) (bn254.G1Affine, error) {
	var p bn254.G1Affine
	if len(buf) != PointSize {
		return p, ErrShortInput
	}
	var x, y fp.Element
	x.SetBytes(buf[0:32])
	y.SetBytes(buf[32:64])
	p.X = x
	p.Y = y
	if !p.IsOnCurve() && !(x.IsZero() && y.IsZero()) {
		return bn254.G1Affine{}, ErrInvalidPoint
	}
	return p, nil
}

func decodeG2(buf []byte) (bn254.G2Affine, error) {
	var p bn254.G2Affine
	if len(buf) != 128 {
		return p, ErrShortInput
	}
	// EVM G2 encoding is (X.A1, X.A0, Y.A1, Y.A0) per EIP-197.
	var x1, x0, y1, y0 fp.Element
	x1.SetBytes(buf[0:32])
	x0.SetBytes(buf[32:64])
	y1.SetBytes(buf[64:96])
	y0.SetBytes(buf[96:128])
	p.X.A0 = x0
	p.X.A1 = x1
	p.Y.A0 = y0
	p.Y.A1 = y1
	if !p.IsOnCurve() && !(x0.IsZero() && x1.IsZero() && y0.IsZero() && y1.IsZero()) {
		return bn254.G2Affine{}, ErrInvalidPoint
	}
	return p, nil
}

func encodeG1(p bn254.G1Affine) []byte {
	out := make([]byte, PointSize)
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	copy(out[0:32], xBytes[:])
	copy(out[32:64], yBytes[:])
	return out
}
