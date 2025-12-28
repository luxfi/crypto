// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

// batchGPU returns (true, nil) when it produced output on the GPU,
// (false, nil) when the GPU was not eligible (callers must fall through),
// or (true, err) when GPU dispatch was attempted and failed.
//
// The luxfi/accel session does not yet expose a real BLAKE3 kernel — its
// crypto_gpu.go falls back to SHA-256 for HashBlake3 (see luxfi/accel
// commit comment). Returning false here forces the CPU path, which is
// already AVX2/NEON-accelerated via zeebo/blake3. When accel ships a real
// BLAKE3 kernel, wire it in here exactly like sha256/gpu.go.
func batchGPU(inputs [][]byte, out [][Size]byte) (handled bool, err error) {
	return false, nil
}
