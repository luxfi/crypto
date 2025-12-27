//go:build cgo

// Package gpu provides GPU-accelerated cryptographic operations.
package gpu

import "sync"

// Buffer pools for hot path allocations.
// Each pool stores byte slices of a specific size to reduce GC pressure.
//
// Pool sizes:
//   - 32 bytes: hash outputs (SHA3-256, BLAKE3), BLS secret keys
//   - 48 bytes: BLS public keys
//   - 64 bytes: SHA3-512 outputs
//   - 96 bytes: BLS signatures
//   - 4032 bytes: ML-DSA secret keys
var (
	pool32 = sync.Pool{
		New: func() any { return make([]byte, 32) },
	}

	pool48 = sync.Pool{
		New: func() any { return make([]byte, 48) },
	}

	pool64 = sync.Pool{
		New: func() any { return make([]byte, 64) },
	}

	pool96 = sync.Pool{
		New: func() any { return make([]byte, 96) },
	}

	pool4032 = sync.Pool{
		New: func() any { return make([]byte, 4032) },
	}
)

// GetBuffer32 retrieves a 32-byte buffer from the pool.
// The returned buffer is zeroed. Caller must call PutBuffer32 when done.
func GetBuffer32() []byte {
	buf := pool32.Get().([]byte)
	clear(buf)
	return buf
}

// PutBuffer32 returns a 32-byte buffer to the pool.
func PutBuffer32(buf []byte) {
	if len(buf) != 32 {
		return
	}
	pool32.Put(buf)
}

// GetBuffer48 retrieves a 48-byte buffer from the pool.
func GetBuffer48() []byte {
	buf := pool48.Get().([]byte)
	clear(buf)
	return buf
}

// PutBuffer48 returns a 48-byte buffer to the pool.
func PutBuffer48(buf []byte) {
	if len(buf) != 48 {
		return
	}
	pool48.Put(buf)
}

// GetBuffer64 retrieves a 64-byte buffer from the pool.
func GetBuffer64() []byte {
	buf := pool64.Get().([]byte)
	clear(buf)
	return buf
}

// PutBuffer64 returns a 64-byte buffer to the pool.
func PutBuffer64(buf []byte) {
	if len(buf) != 64 {
		return
	}
	pool64.Put(buf)
}

// GetBuffer96 retrieves a 96-byte buffer from the pool.
func GetBuffer96() []byte {
	buf := pool96.Get().([]byte)
	clear(buf)
	return buf
}

// PutBuffer96 returns a 96-byte buffer to the pool.
func PutBuffer96(buf []byte) {
	if len(buf) != 96 {
		return
	}
	pool96.Put(buf)
}

// GetBuffer4032 retrieves a 4032-byte buffer from the pool.
func GetBuffer4032() []byte {
	buf := pool4032.Get().([]byte)
	clear(buf)
	return buf
}

// PutBuffer4032 returns a 4032-byte buffer to the pool.
func PutBuffer4032(buf []byte) {
	if len(buf) != 4032 {
		return
	}
	pool4032.Put(buf)
}

// SHA3_256Into is defined in crypto.go with CGO acceleration.
// Use it with GetBuffer32/PutBuffer32 to avoid allocations.

// SHA3_512Into computes SHA3-512 hash into the provided buffer.
func SHA3_512Into(out, data []byte) {
	if len(out) < 64 {
		return
	}
	if len(data) == 0 {
		clear(out[:64])
		return
	}
	hash := SHA3_512(data)
	copy(out[:64], hash)
}

// BLAKE3Into computes BLAKE3 hash into the provided buffer.
func BLAKE3Into(out, data []byte) {
	if len(out) < 32 {
		return
	}
	if len(data) == 0 {
		clear(out[:32])
		return
	}
	hash := BLAKE3(data)
	copy(out[:32], hash)
}
