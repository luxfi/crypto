//go:build cgo
// +build cgo

// Centralized cgo wrapper to avoid duplicate linking
// All other packages should import this instead of having their own cgo directives
package luxlink

/*
#cgo pkg-config: lux-crypto lux-gpu lux-lattice
#include <lux/crypto/crypto.h>
#include <lux/crypto/metal_mldsa.h>
#include <lux/crypto/metal_mlkem.h>
#include <lux/crypto/metal_slhdsa.h>
#include <lux/crypto/metal_ipa.h>
#include <lux/gpu/gpu.h>
*/
import "C"

// Export Go APIs that other packages can call
// This ensures libraries are only linked once
