// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kats

import (
	"encoding/hex"
)

// mustDecodeHex is the helper the generated vectors_mldsaXX.go
// files call to inline byte literals. A malformed input is a
// compile-time defect — we panic so tests fail loudly at init
// rather than producing silent zero-byte slices.
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("kats: bad hex literal: " + err.Error())
	}
	return b
}
