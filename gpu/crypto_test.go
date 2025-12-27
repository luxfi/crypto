//go:build !cgo

package gpu

import (
	"errors"
	"testing"
)

func TestNoCGO_GPUAvailable(t *testing.T) {
	if GPUAvailable() {
		t.Error("GPUAvailable should return false without CGO")
	}

	backend := GetBackend()
	if backend != "CPU (CGO disabled)" {
		t.Errorf("GetBackend = %q, want %q", backend, "CPU (CGO disabled)")
	}

	t.Logf("Backend: %s (CGO disabled)", backend)
}

func TestNoCGO_BLSReturnsError(t *testing.T) {
	_, err := BLSKeygen(nil)
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("BLSKeygen error = %v, want ErrCGORequired", err)
	}

	_, err = BLSSecretKeyToPublicKey(make([]byte, 32))
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("BLSSecretKeyToPublicKey error = %v, want ErrCGORequired", err)
	}

	_, err = BLSSign(make([]byte, 32), make([]byte, 32))
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("BLSSign error = %v, want ErrCGORequired", err)
	}

	if BLSVerify(nil, nil, nil) {
		t.Error("BLSVerify should return false without CGO")
	}

	t.Log("All BLS functions correctly return ErrCGORequired")
}

func TestNoCGO_MLDSAReturnsError(t *testing.T) {
	_, _, err := MLDSAKeygen(nil)
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("MLDSAKeygen error = %v, want ErrCGORequired", err)
	}

	_, err = MLDSASign(make([]byte, 4032), []byte("test"))
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("MLDSASign error = %v, want ErrCGORequired", err)
	}

	if MLDSAVerify(nil, nil, nil) {
		t.Error("MLDSAVerify should return false without CGO")
	}

	t.Log("All ML-DSA functions correctly return ErrCGORequired")
}

func TestNoCGO_ThresholdReturnsError(t *testing.T) {
	_, err := NewThresholdContext(3, 5)
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("NewThresholdContext error = %v, want ErrCGORequired", err)
	}

	// Test methods on nil context (should not panic)
	var ctx *ThresholdContext
	ctx.Close() // Should not panic

	_, _, err = ctx.Keygen(nil)
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("Keygen error = %v, want ErrCGORequired", err)
	}

	t.Log("All threshold functions correctly return ErrCGORequired")
}

func TestNoCGO_HashReturnsNil(t *testing.T) {
	data := []byte("test data")

	if hash := SHA3_256(data); hash != nil {
		t.Error("SHA3_256 should return nil without CGO")
	}

	if hash := SHA3_512(data); hash != nil {
		t.Error("SHA3_512 should return nil without CGO")
	}

	if hash := BLAKE3(data); hash != nil {
		t.Error("BLAKE3 should return nil without CGO")
	}

	_, err := BatchHash([][]byte{data}, HashTypeSHA3_256)
	if !errors.Is(err, ErrCGORequired) {
		t.Errorf("BatchHash error = %v, want ErrCGORequired", err)
	}

	t.Log("All hash functions correctly return nil/ErrCGORequired")
}

func TestNoCGO_ConsensusVerifyBlock(t *testing.T) {
	if ConsensusVerifyBlock(nil, nil, nil, nil, nil) {
		t.Error("ConsensusVerifyBlock should return false without CGO")
	}

	t.Log("ConsensusVerifyBlock correctly returns false")
}
