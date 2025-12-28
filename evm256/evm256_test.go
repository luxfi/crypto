package evm256

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAddIdentity(t *testing.T) {
	// 0 + 0 = 0
	zero := make([]byte, 2*PointSize)
	got, err := Add(zero)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, PointSize)
	if !bytes.Equal(got, want) {
		t.Errorf("Add(0,0) = %x; want %x", got, want)
	}
}

func TestScalarMulZero(t *testing.T) {
	// G * 0 = 0 (where G is generator). Use generator from EIP-197 test vector.
	gen, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001" +
		"0000000000000000000000000000000000000000000000000000000000000002")
	zero := make([]byte, 32)
	input := append(gen, zero...)
	got, err := ScalarMul(input)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, PointSize)
	if !bytes.Equal(got, want) {
		t.Errorf("G*0 = %x; want %x", got, want)
	}
}

func TestPairingCheckEmpty(t *testing.T) {
	got, err := PairingCheck(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 || got[31] != 1 {
		t.Errorf("empty pairing = %x; want 32-byte 0x..01", got)
	}
}

func TestPairingCheckBadLength(t *testing.T) {
	if _, err := PairingCheck(make([]byte, 100)); err != ErrInvalidPairings {
		t.Errorf("got %v want %v", err, ErrInvalidPairings)
	}
}
