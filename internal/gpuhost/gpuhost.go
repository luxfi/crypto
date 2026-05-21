// Package gpuhost provides the runtime hook between luxfi/crypto algorithm
// packages and github.com/luxfi/accel.
//
// gpuhost owns a singleton accel session and exposes thin helpers that
// algorithm packages call to ask "is GPU available right now?" and to
// fetch the session for batch operations.
//
// gpuhost is internal: callers outside luxfi/crypto must use the public
// dispatchers in each algorithm package, which call gpuhost.
package gpuhost

import (
	"sync"

	"github.com/luxfi/accel"
)

var (
	once     sync.Once
	sess     *accel.Session
	initErr  error
	available bool
)

// Init initialises accel exactly once and creates the shared session.
// Safe to call from any goroutine. Subsequent calls are no-ops.
func Init() {
	once.Do(func() {
		if err := accel.Init(); err != nil {
			initErr = err
			return
		}
		if !accel.Available() {
			return // accel ready but no devices; available stays false
		}
		s, err := accel.NewSession()
		if err != nil {
			initErr = err
			return
		}
		sess = s
		available = true
	})
}

// Available returns true when an accel session was successfully created
// and is currently usable. Algorithm packages check this before deciding
// to dispatch to the GPU path.
func Available() bool {
	Init()
	return available
}

// Session returns the shared accel.Session, or nil if no GPU is available.
// Callers must check Available() first or guard nil at the call site.
func Session() *accel.Session {
	Init()
	return sess
}

// InitError returns the last error from accel initialisation. It is
// non-nil only when the accel library itself failed to load; an
// "accel works, no device" state returns nil.
func InitError() error {
	Init()
	return initErr
}

// Provenance captures, at the moment of the call, exactly which
// substrate the algorithm dispatchers will reach when they ask gpuhost
// for a session. This is the auditable evidence a reviewer asks for
// when they want to confirm a "GPU accelerated" claim is not vapor.
//
// The fields are intentionally narrow and observable:
//
//   - AccelInitialised: did accel.Init() return without error.
//   - DeviceAvailable:  did accel report any device after init.
//   - SessionLive:      did we actually allocate a session.
//
// Algorithm packages publish their own thin layer on top of this that
// also reports whether the plugin's strong symbol for that algorithm
// is resolved (e.g. whether lux_slhdsa_verify_batch is the LUX_NOT_SUPPORTED
// stub or a strong override from a loaded plugin).
type Provenance struct {
	AccelInitialised bool
	DeviceAvailable  bool
	SessionLive      bool
}

// Snapshot returns the current Provenance. Side-effect-free except for
// the lazy accel.Init() inside the underlying Init() — calling it before
// any algorithm dispatch is the canonical way to print "what would
// happen if I called Batch right now."
func Snapshot() Provenance {
	Init()
	return Provenance{
		AccelInitialised: initErr == nil,
		DeviceAvailable:  available && sess != nil,
		SessionLive:      sess != nil,
	}
}
