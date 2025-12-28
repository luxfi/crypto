package bn254

import "testing"

// Smoke test: ensure the type aliases compile and PairingCheck returns true
// for the trivial empty input.
func TestPairingCheckEmpty(t *testing.T) {
	if !PairingCheck(nil, nil) {
		t.Error("PairingCheck(nil, nil) = false; want true")
	}
}
