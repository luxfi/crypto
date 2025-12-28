package gpu

import "testing"

func TestProbe(t *testing.T) {
	// Available is allowed to be true or false depending on host;
	// just exercise the API.
	_ = Available()

	if Available() {
		if Backend() == "" {
			t.Error("Available()=true but Backend() empty")
		}
	} else {
		if Backend() != "" {
			t.Errorf("Available()=false but Backend()=%q", Backend())
		}
	}

	if Version() == "" {
		t.Error("Version() is empty")
	}

	// Devices must be non-nil only when Available is true.
	if Available() && Devices() == nil {
		t.Error("Available()=true but Devices() is nil")
	}
}
