// Copyright 2025 The Lux Authors
// This file is part of the Lux library.
//
// The Lux library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Lux library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Lux library. If not, see <http://www.gnu.org/licenses/>.

// Package hexutil implements hex encoding with 0x prefix.
// This encoding is used by the Ethereum RPC API to transport binary data in JSON payloads.
package hexutil

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
)

const uintBits = 32 << (uint64(^uint(0)) >> 63)

// Errors
var (
	ErrEmptyString   = &decError{"empty hex string"}
	ErrSyntax        = &decError{"invalid hex string"}
	ErrMissingPrefix = &decError{"hex string without 0x prefix"}
	ErrOddLength     = &decError{"hex string of odd length"}
	ErrEmptyNumber   = &decError{"hex string \"0x\""}
	ErrLeadingZero   = &decError{"hex number with leading zero digits"}
	ErrUint64Range   = &decError{"hex number > 64 bits"}
	ErrUintRange     = &decError{fmt.Sprintf("hex number > %d bits", uintBits)}
	ErrBig256Range   = &decError{"hex number > 256 bits"}
)

type decError struct{ msg string }

func (err decError) Error() string { return err.msg }

// Decode decodes a hex string with 0x prefix.
func Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrEmptyString
	}
	if !has0xPrefix(input) {
		return nil, ErrMissingPrefix
	}
	b, err := hex.DecodeString(input[2:])
	if err != nil {
		err = mapError(err)
	}
	return b, err
}

// MustDecode decodes a hex string with 0x prefix. It panics for invalid input.
func MustDecode(input string) []byte {
	dec, err := Decode(input)
	if err != nil {
		panic(err)
	}
	return dec
}

// Encode encodes b as a hex string with 0x prefix.
func Encode(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, "0x")
	hex.Encode(enc[2:], b)
	return string(enc)
}

// DecodeUint64 decodes a hex string with 0x prefix as a quantity.
func DecodeUint64(input string) (uint64, error) {
	raw, err := checkNumber(input)
	if err != nil {
		return 0, err
	}
	dec, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		err = mapError(err)
	}
	return dec, err
}

// MustDecodeUint64 decodes a hex string with 0x prefix as a quantity.
// It panics for invalid input.
func MustDecodeUint64(input string) uint64 {
	dec, err := DecodeUint64(input)
	if err != nil {
		panic(err)
	}
	return dec
}

// EncodeUint64 encodes i as a hex string with 0x prefix.
func EncodeUint64(i uint64) string {
	enc := make([]byte, 2, 10)
	copy(enc, "0x")
	return string(strconv.AppendUint(enc, i, 16))
}

// DecodeBig decodes a hex string with 0x prefix as a quantity.
// Numbers larger than 256 bits are not accepted.
func DecodeBig(input string) (*big.Int, error) {
	raw, err := checkNumber(input)
	if err != nil {
		return nil, err
	}
	if len(raw) > 64 {
		return nil, ErrBig256Range
	}
	words := make([]big.Word, len(raw)/16+1)
	end := len(raw)
	for i := range words {
		start := end - 16
		if start < 0 {
			start = 0
		}
		for ri := start; ri < end; ri++ {
			nib := decodeNibble(raw[ri])
			if nib == badNibble {
				return nil, ErrSyntax
			}
			words[i] *= 16
			words[i] += big.Word(nib)
		}
		end = start
	}
	dec := new(big.Int).SetBits(words)
	return dec, nil
}

// MustDecodeBig decodes a hex string with 0x prefix as a quantity.
// It panics for invalid input.
func MustDecodeBig(input string) *big.Int {
	dec, err := DecodeBig(input)
	if err != nil {
		panic(err)
	}
	return dec
}

// EncodeBig encodes bigint as a hex string with 0x prefix.
func EncodeBig(bigint *big.Int) string {
	if sign := bigint.Sign(); sign == 0 {
		return "0x0"
	} else if sign > 0 {
		return "0x" + bigint.Text(16)
	} else {
		return "-0x" + bigint.Text(16)[1:]
	}
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// checkNumber checks that str is valid and returns it without the 0x prefix.
func checkNumber(input string) (raw string, err error) {
	if len(input) == 0 {
		return "", ErrEmptyString
	}
	if !has0xPrefix(input) {
		return "", ErrMissingPrefix
	}
	input = input[2:]
	if len(input) == 0 {
		return "", ErrEmptyNumber
	}
	if len(input) > 1 && input[0] == '0' {
		return "", ErrLeadingZero
	}
	return input, nil
}

const badNibble = ^uint64(0)

func decodeNibble(in byte) uint64 {
	switch {
	case in >= '0' && in <= '9':
		return uint64(in - '0')
	case in >= 'A' && in <= 'F':
		return uint64(in - 'A' + 10)
	case in >= 'a' && in <= 'f':
		return uint64(in - 'a' + 10)
	default:
		return badNibble
	}
}

func mapError(err error) error {
	if err, ok := err.(*strconv.NumError); ok {
		switch err.Err {
		case strconv.ErrRange:
			return ErrUint64Range
		case strconv.ErrSyntax:
			return ErrSyntax
		}
	}
	if _, ok := err.(hex.InvalidByteError); ok {
		return ErrSyntax
	}
	if err == hex.ErrLength {
		return ErrOddLength
	}
	return err
}

// Big marshals/unmarshals as a JSON string with 0x prefix.
// The zero value marshals as "0x0".
type Big big.Int

// NewBig creates a new Big from a big.Int.
func NewBig(x *big.Int) *Big {
	return (*Big)(x)
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *Big) UnmarshalJSON(input []byte) error {
	if !isString(input) {
		return errNonString(bigT)
	}
	return wrapTypeError(b.UnmarshalText(input[1:len(input)-1]), bigT)
}

// UnmarshalText implements encoding.TextUnmarshaler
func (b *Big) UnmarshalText(input []byte) error {
	raw, err := checkNumberText(input)
	if err != nil {
		return err
	}
	if len(raw) > 64 {
		return ErrBig256Range
	}
	words := make([]big.Word, len(raw)/16+1)
	end := len(raw)
	for i := range words {
		start := end - 16
		if start < 0 {
			start = 0
		}
		for ri := start; ri < end; ri++ {
			nib := decodeNibble(raw[ri])
			if nib == badNibble {
				return ErrSyntax
			}
			words[i] *= 16
			words[i] += big.Word(nib)
		}
		end = start
	}
	(*big.Int)(b).SetBits(words)
	return nil
}

// MarshalText implements encoding.TextMarshaler
func (b Big) MarshalText() ([]byte, error) {
	return []byte(EncodeBig((*big.Int)(&b))), nil
}

// String returns the hex encoding of b.
func (b *Big) String() string {
	return EncodeBig((*big.Int)(b))
}

// Uint64 marshals/unmarshals as a JSON string with 0x prefix.
// The zero value marshals as "0x0".
type Uint64 uint64

// UnmarshalJSON implements json.Unmarshaler.
func (b *Uint64) UnmarshalJSON(input []byte) error {
	if !isString(input) {
		return errNonString(uint64T)
	}
	return wrapTypeError(b.UnmarshalText(input[1:len(input)-1]), uint64T)
}

// UnmarshalText implements encoding.TextUnmarshaler
func (b *Uint64) UnmarshalText(input []byte) error {
	raw, err := checkNumberText(input)
	if err != nil {
		return err
	}
	if len(raw) > 16 {
		return ErrUint64Range
	}
	var dec uint64
	for _, byte := range raw {
		nib := decodeNibble(byte)
		if nib == badNibble {
			return ErrSyntax
		}
		dec *= 16
		dec += nib
	}
	*b = Uint64(dec)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (b Uint64) MarshalText() ([]byte, error) {
	return []byte(EncodeUint64(uint64(b))), nil
}

// String returns the hex encoding of b.
func (b Uint64) String() string {
	return EncodeUint64(uint64(b))
}

// Uint marshals/unmarshals as a JSON string with 0x prefix.
// The zero value marshals as "0x0".
type Uint uint

// UnmarshalJSON implements json.Unmarshaler.
func (b *Uint) UnmarshalJSON(input []byte) error {
	if !isString(input) {
		return errNonString(uintT)
	}
	return wrapTypeError(b.UnmarshalText(input[1:len(input)-1]), uintT)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (b *Uint) UnmarshalText(input []byte) error {
	raw, err := checkNumberText(input)
	if err != nil {
		return err
	}
	if len(raw) > 64/4 {
		return ErrUintRange
	}
	var dec uint
	for _, byte := range raw {
		nib := decodeNibble(byte)
		if nib == badNibble {
			return ErrSyntax
		}
		dec *= 16
		dec += uint(nib)
	}
	*b = Uint(dec)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (b Uint) MarshalText() ([]byte, error) {
	return []byte(EncodeUint64(uint64(b))), nil
}

// String returns the hex encoding of b.
func (b Uint) String() string {
	return EncodeUint64(uint64(b))
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

// UnmarshalJSON implements json.Unmarshaler.
func (b *Bytes) UnmarshalJSON(input []byte) error {
	if !isString(input) {
		return errNonString(bytesT)
	}
	return wrapTypeError(b.UnmarshalText(input[1:len(input)-1]), bytesT)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (b *Bytes) UnmarshalText(input []byte) error {
	raw, err := checkText(input, true)
	if err != nil {
		return err
	}
	dec := make([]byte, len(raw)/2)
	if _, err = hex.Decode(dec, raw); err != nil {
		err = mapError(err)
	} else {
		*b = dec
	}
	return err
}

// String returns the hex encoding of b.
func (b Bytes) String() string {
	return Encode(b)
}

// UnmarshalFixedJSON decodes the input as a string with 0x prefix. The length of out
// determines the required input length. This function is commonly used to implement the
// UnmarshalJSON method for fixed-size types.
func UnmarshalFixedJSON(typ reflect.Type, input, out []byte) error {
	if !isString(input) {
		return errNonString(typ)
	}
	return wrapTypeError(UnmarshalFixedText(typ.String(), input[1:len(input)-1], out), typ)
}

// UnmarshalFixedText decodes the input as a string with 0x prefix. The length of out
// determines the required input length. This function is commonly used to implement the
// UnmarshalText method for fixed-size types.
func UnmarshalFixedText(typname string, input, out []byte) error {
	raw, err := checkText(input, true)
	if err != nil {
		return err
	}
	if len(raw)/2 != len(out) {
		return fmt.Errorf("hex string has length %d, want %d for %s", len(raw), len(out)*2, typname)
	}
	// Pre-verify syntax before modifying out.
	for _, b := range raw {
		if decodeNibble(b) == badNibble {
			return ErrSyntax
		}
	}
	hex.Decode(out, raw)
	return nil
}

// UnmarshalFixedUnprefixedText decodes the input as a string with optional 0x prefix. The
// length of out determines the required input length. This function is commonly used to
// implement the UnmarshalText method for fixed-size types.
func UnmarshalFixedUnprefixedText(typname string, input, out []byte) error {
	raw, err := checkText(input, false)
	if err != nil {
		return err
	}
	if len(raw)/2 != len(out) {
		return fmt.Errorf("hex string has length %d, want %d for %s", len(raw), len(out)*2, typname)
	}
	// Pre-verify syntax before modifying out.
	for _, b := range raw {
		if decodeNibble(b) == badNibble {
			return ErrSyntax
		}
	}
	hex.Decode(out, raw)
	return nil
}

// MustParseBig256 parses s as a 256 bit big integer and panics if the string is invalid.
func MustParseBig256(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 0)
	if !ok {
		panic("invalid 256 bit integer: " + s)
	}
	if v.BitLen() > 256 {
		panic("value exceeds 256 bits: " + s)
	}
	return v
}

// Helper functions

func isString(input []byte) bool {
	return len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"'
}

func errNonString(typ reflect.Type) error {
	return &json.UnmarshalTypeError{Value: "non-string", Type: typ}
}

func wrapTypeError(err error, typ reflect.Type) error {
	if _, ok := err.(*decError); ok {
		return &json.UnmarshalTypeError{Value: err.Error(), Type: typ}
	}
	return err
}

func checkNumberText(input []byte) (raw []byte, err error) {
	if len(input) == 0 {
		return nil, ErrEmptyString
	}
	if !bytesHave0xPrefix(input) {
		return nil, ErrMissingPrefix
	}
	input = input[2:]
	if len(input) == 0 {
		return nil, ErrEmptyNumber
	}
	if len(input) > 1 && input[0] == '0' {
		return nil, ErrLeadingZero
	}
	return input, nil
}

func bytesHave0xPrefix(input []byte) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

func checkText(input []byte, wantPrefix bool) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil // empty strings are allowed
	}
	if bytesHave0xPrefix(input) {
		input = input[2:]
	} else if wantPrefix {
		return nil, ErrMissingPrefix
	}
	if len(input)%2 != 0 {
		return nil, ErrOddLength
	}
	return input, nil
}

// Type constants for error handling
var (
	bigT    = reflect.TypeOf((*Big)(nil))
	uint64T = reflect.TypeOf(Uint64(0))
	uintT   = reflect.TypeOf(Uint(0))
	bytesT  = reflect.TypeOf(Bytes(nil))
)