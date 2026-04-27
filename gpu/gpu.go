// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu exposes the runtime status of the GPU acceleration layer used
// by luxfi/crypto.
//
// In normal use, callers should NOT call this package directly. Each
// algorithm package (keccak, sha256, bls, mldsa, ...) decides at the call
// site whether to dispatch to the GPU based on backend.Default() and the
// batch threshold. This package is a single, narrow surface so consumers
// can probe the status of the layer for diagnostics and monitoring.
package gpu

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// Available returns true when an accel session was successfully created
// and at least one backend is reporting available devices.
func Available() bool { return gpuhost.Available() }

// Backend returns the name of the active backend ("metal", "cuda", "webgpu",
// or "" when no GPU is available).
func Backend() string {
	if !Available() {
		return ""
	}
	return gpuhost.Session().Backend().String()
}

// Devices returns the list of devices visible to the accel layer.
func Devices() []accel.DeviceInfo {
	if !Available() {
		return nil
	}
	return accel.Devices()
}

// Version returns the underlying accel library version string.
func Version() string { return accel.GetVersion() }
