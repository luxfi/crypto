// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Common types for precompile package

package precompile

import "encoding/hex"

// Address represents a 20-byte Ethereum address
type Address [20]byte

// HexToAddress returns Address with byte values of s.
func HexToAddress(s string) Address {
	var addr Address
	// Remove 0x prefix if present
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	b, _ := hex.DecodeString(s)
	if len(b) > 20 {
		b = b[len(b)-20:]
	}
	copy(addr[20-len(b):], b)
	return addr
}

// Bytes returns the byte representation of the address
func (a Address) Bytes() []byte {
	return a[:]
}

// String returns the hex string representation of the address
func (a Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}
