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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

// MustDecode decodes a hex string with 0x prefix. It panics for invalid input.
func MustDecode(input string) []byte {
	dec, err := Decode(input)
	if err != nil {
		panic(err)
	}
	return dec
}

// Decode decodes a hex string with 0x prefix.
func Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if !has0xPrefix(input) {
		return nil, fmt.Errorf("hex string without 0x prefix")
	}
	b, err := hex.DecodeString(input[2:])
	if err != nil {
		return nil, err
	}
	return b, nil
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// Bytes marshals/unmarshals as a JSON string with 0x prefix.
// The empty slice marshals as "0x".
type Bytes []byte

// MarshalText implements encoding.TextMarshaler
func (b Bytes) MarshalText() ([]byte, error) {
	result := make([]byte, len(b)*2+2)
	copy(result, `0x`)
	hex.Encode(result[2:], b)
	return result, nil
}

// UnmarshalFixedJSON decodes the input as a string with 0x prefix and required length. The output
// given is assumed to be large enough.
func UnmarshalFixedJSON(typ reflect.Type, input, out []byte) error {
	if !isString(input) {
		return fmt.Errorf("fixed bytes type %v: input must be a JSON string", typ)
	}
	return wrapTypeError(decodeFixedHex(typ, input[1:len(input)-1], out), typ)
}

func isString(input []byte) bool {
	return len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"'
}

func wrapTypeError(err error, typ reflect.Type) error {
	if _, ok := err.(*decError); ok {
		return &json.UnmarshalTypeError{Value: err.Error(), Type: typ}
	}
	return err
}

type decError struct{ msg string }

func (err decError) Error() string { return err.msg }

func decodeFixedHex(typ reflect.Type, input, out []byte) error {
	if len(input) == 0 {
		return nil
	}
	if !has0xPrefix(string(input)) {
		return &decError{msg: "missing 0x prefix"}
	}
	input = input[2:]
	wantLen := len(out) * 2
	if len(input) == 0 {
		return &decError{fmt.Sprintf("empty hex string, want %d hex digits", wantLen)}
	}
	if len(input) != wantLen {
		return &decError{fmt.Sprintf("got %d hex digits, want %d", len(input), wantLen)}
	}
	// Decode hex string into out
	if _, err := hex.Decode(out, input); err != nil {
		return &decError{err.Error()}
	}
	return nil
}
