//go:build cgo && luxcpp

// Centralized cgo wrapper to avoid duplicate linking
// All other packages should import this instead of having their own cgo directives
//
// The `luxcpp` tag is opt-in because this is the ONE package in the repo that
// cannot build without the luxcpp C++ artifacts installed. On the runner:
//
//	# [pkg-config --cflags -- lux-crypto lux-gpu lux-lattice]
//	Package lux-crypto was not found in the pkg-config search path.
//	FAIL github.com/luxfi/crypto/cgo [build failed]
//
// which failed the whole cgo leg of the test matrix -- and it was the only
// package that did, so every other test was reported red for this one.
//
// It cannot simply be fetched: luxfi/luxcpp publishes NO releases, so accel's
// `make fetch-deps` has nothing to download either, which is why accel's own CI
// runs its Go tests with CGO_ENABLED=0. Until luxcpp ships artifacts, this stays
// opt-in and is built by whoever has them:
//
//	go build -tags luxcpp ./cgo/
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
