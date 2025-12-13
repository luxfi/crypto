// Copyright 2025 The luxfi Authors
// This file is part of the luxfi library.
//
// The luxfi library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The luxfi library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the luxfi library. If not, see <http://www.gnu.org/licenses/>.

package bitutil

// TestBytes tests if all bytes in the slice are zero
func TestBytes(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}
