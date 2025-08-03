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
	"bytes"
	"encoding/binary"
)

// EncodeToBytes encodes the given values to RLP.
// This is a minimal implementation specifically for CreateAddress.
func EncodeToBytes(val interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, val interface{}) error {
	switch v := val.(type) {
	case []interface{}:
		return encodeList(buf, v)
	case Address:
		return encodeBytes(buf, v[:])
	case uint64:
		return encodeUint64(buf, v)
	default:
		return nil
	}
}

func encodeBytes(buf *bytes.Buffer, b []byte) error {
	if len(b) == 1 && b[0] <= 0x7F {
		buf.WriteByte(b[0])
	} else if len(b) <= 55 {
		buf.WriteByte(byte(0x80 + len(b)))
		buf.Write(b)
	} else {
		lenBytes := intToBytes(uint64(len(b)))
		buf.WriteByte(byte(0xB7 + len(lenBytes)))
		buf.Write(lenBytes)
		buf.Write(b)
	}
	return nil
}

func encodeUint64(buf *bytes.Buffer, i uint64) error {
	if i == 0 {
		buf.WriteByte(0x80)
	} else if i < 128 {
		buf.WriteByte(byte(i))
	} else {
		b := intToBytes(i)
		return encodeBytes(buf, b)
	}
	return nil
}

func encodeList(buf *bytes.Buffer, list []interface{}) error {
	var contentBuf bytes.Buffer
	for _, elem := range list {
		if err := encode(&contentBuf, elem); err != nil {
			return err
		}
	}
	content := contentBuf.Bytes()

	if len(content) <= 55 {
		buf.WriteByte(byte(0xC0 + len(content)))
		buf.Write(content)
	} else {
		lenBytes := intToBytes(uint64(len(content)))
		buf.WriteByte(byte(0xF7 + len(lenBytes)))
		buf.Write(lenBytes)
		buf.Write(content)
	}
	return nil
}

func intToBytes(i uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], i)

	// Find first non-zero byte
	for idx := 0; idx < 8; idx++ {
		if buf[idx] != 0 {
			return buf[idx:]
		}
	}
	return nil
}
