// Copyright (C) 2020-2025, Lux Industries Inc
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package utils

import (
	"fmt"
	"math/big"
)

// PaddedBigBytes encodes a big integer as a big-endian byte slice. The length
// of the slice is at least n bytes.
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	return bigint.FillBytes(ret)
}

// MustParseBig256 parses a hex or decimal string as a quantity of at most
// 256 bits. The result has 256 bits (32 bytes). Leading zeros are kept as required.
func MustParseBig256(s string) *big.Int {
	v, ok := ParseBig256(s)
	if !ok {
		panic(fmt.Sprintf("invalid 256 bit integer: %s", s))
	}
	return v
}

// ParseBig256 parses a hex or decimal string as a quantity of at most
// 256 bits. The result has 256 bits (32 bytes). Leading zeros are kept as required.
func ParseBig256(s string) (*big.Int, bool) {
	if s == "" {
		return nil, false
	}
	var bigint *big.Int
	var ok bool
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		bigint, ok = new(big.Int).SetString(s[2:], 16)
	} else {
		bigint, ok = new(big.Int).SetString(s, 10)
	}
	if !ok || bigint.BitLen() > 256 {
		return nil, false
	}
	return bigint, true
}