//go:build !cgo

// Package gpu provides GPU-accelerated cryptographic operations.
// This file provides stub implementations when CGO is disabled.
package gpu

import (
	"errors"
)

var ErrCGORequired = errors.New("CGO required for GPU acceleration")

// Sizes
const (
	BLSSecretKeySize  = 32
	BLSPublicKeySize  = 48
	BLSSignatureSize  = 96
	BLSMessageSize    = 32

	MLDSASecretKeySize  = 4032
	MLDSAPublicKeySize  = 1952
	MLDSASignatureSize  = 3309

	HashTypeSHA3_256 = 0
	HashTypeSHA3_512 = 1
	HashTypeBLAKE3   = 2
)

func GPUAvailable() bool { return false }
func GetBackend() string { return "CPU (CGO disabled)" }
func ClearCache()        {}

func BLSKeygen(seed []byte) ([]byte, error) { return nil, ErrCGORequired }
func BLSSecretKeyToPublicKey(sk []byte) ([]byte, error) { return nil, ErrCGORequired }
func BLSSign(sk, msg []byte) ([]byte, error) { return nil, ErrCGORequired }
func BLSVerify(sig, pk, msg []byte) bool { return false }
func BLSAggregateSignatures(sigs [][]byte) ([]byte, error) { return nil, ErrCGORequired }
func BLSAggregatePublicKeys(pks [][]byte) ([]byte, error) { return nil, ErrCGORequired }
func BLSVerifyAggregated(aggSig, aggPK, msg []byte) bool { return false }
func BLSBatchVerify(sigs, pks, msgs [][]byte) ([]bool, error) { return nil, ErrCGORequired }

func MLDSAKeygen(seed []byte) (pk, sk []byte, err error) { return nil, nil, ErrCGORequired }
func MLDSASign(sk, msg []byte) ([]byte, error) { return nil, ErrCGORequired }
func MLDSAVerify(sig, msg, pk []byte) bool { return false }
func MLDSABatchVerify(sigs, msgs [][]byte, pks [][]byte) ([]bool, error) { return nil, ErrCGORequired }

type ThresholdContext struct{}
func NewThresholdContext(t, n uint32) (*ThresholdContext, error) { return nil, ErrCGORequired }
func (tc *ThresholdContext) Close() {}
func (tc *ThresholdContext) Keygen(seed []byte) (shares [][]byte, pk []byte, err error) { return nil, nil, ErrCGORequired }
func (tc *ThresholdContext) PartialSign(shareIndex uint32, share, msg []byte) ([]byte, error) { return nil, ErrCGORequired }
func (tc *ThresholdContext) Combine(partialSigs [][]byte, indices []uint32) ([]byte, error) { return nil, ErrCGORequired }
func (tc *ThresholdContext) Verify(sig, pk, msg []byte) bool { return false }

func SHA3_256(data []byte) []byte { return nil }
func SHA3_512(data []byte) []byte { return nil }
func BLAKE3(data []byte) []byte { return nil }
func BatchHash(inputs [][]byte, hashType int) ([][]byte, error) { return nil, ErrCGORequired }

func ConsensusVerifyBlock(blsSigs, blsPKs [][]byte, thresholdSig, thresholdPK, blockHash []byte) bool { return false }
