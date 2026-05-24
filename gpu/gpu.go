// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu is the public probe surface for the GPU acceleration layer
// used by luxfi/crypto.
//
// It delegates every call to github.com/luxfi/crypto/backend — the canonical
// runtime substrate selector. Callers writing new code should prefer
// backend.Probe() / backend.GPUAvailable(); this package stays for back-compat
// with consumers that already import "github.com/luxfi/crypto/gpu".
package gpu

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
)

// Available reports whether the GPU substrate is reachable. Equivalent to
// backend.GPUAvailable().
func Available() bool { return backend.GPUAvailable() }

// Backend names the active accel backend ("metal" | "cuda" | "webgpu") or
// "" when no GPU is available. Equivalent to backend.Probe().GPUBackend.
func Backend() string { return backend.Probe().GPUBackend }

// Devices returns the list of devices visible to the accel layer, or nil
// when no GPU is available.
func Devices() []accel.DeviceInfo {
	if !Available() {
		return nil
	}
	return accel.Devices()
}

// Version returns the underlying accel library version string. Equivalent
// to backend.Probe().AccelVersion.
func Version() string { return accel.GetVersion() }
