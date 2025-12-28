package backend

import (
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Backend
		ok   bool
	}{
		{"", Auto, true},
		{"auto", Auto, true},
		{"AUTO", Auto, true},
		{"vanilla", Vanilla, true},
		{"go", Vanilla, true},
		{"pure", Vanilla, true},
		{"cgo", CGo, true},
		{"c", CGo, true},
		{"native", CGo, true},
		{"gpu", GPU, true},
		{"accel", GPU, true},
		{"banana", Auto, false},
	}
	for _, tc := range cases {
		got, ok := Parse(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Parse(%q) = (%v, %v); want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDefaultAndSetDefault(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	for _, b := range []Backend{Auto, Vanilla, CGo, GPU} {
		SetDefault(b)
		if got := Default(); got != b {
			t.Errorf("after SetDefault(%v) Default() = %v", b, got)
		}
	}
}

func TestResolveVanillaAlwaysAvailable(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	SetDefault(Auto)
	if got := Resolve(false, false); got != Vanilla {
		t.Fatalf("Resolve(false, false) = %v; want Vanilla", got)
	}
}

func TestResolveAutoPrefersGPU(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	SetDefault(Auto)
	if got := Resolve(true, true); got != GPU {
		t.Fatalf("Resolve(true, true) auto = %v; want GPU", got)
	}
	if got := Resolve(false, true); got != CGo {
		t.Fatalf("Resolve(false, true) auto = %v; want CGo", got)
	}
}

func TestResolveExplicitForcesFallback(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	SetDefault(GPU)
	if got := Resolve(false, true); got != CGo {
		t.Fatalf("Resolve(false, true) gpu-forced = %v; want CGo (fallback)", got)
	}
	if got := Resolve(false, false); got != Vanilla {
		t.Fatalf("Resolve(false, false) gpu-forced = %v; want Vanilla (fallback)", got)
	}
	SetDefault(CGo)
	if got := Resolve(true, false); got != Vanilla {
		t.Fatalf("Resolve(true, false) cgo-forced = %v; want Vanilla (fallback)", got)
	}
}

func TestStringRoundTrip(t *testing.T) {
	for _, b := range []Backend{Auto, Vanilla, CGo, GPU} {
		got, ok := Parse(b.String())
		if !ok || got != b {
			t.Errorf("round-trip %v: Parse(%q) = (%v, %v)", b, b.String(), got, ok)
		}
	}
}

func TestEnvOverride(t *testing.T) {
	// Saved current state.
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	// We cannot re-trigger init() without process restart; emulate by
	// re-parsing here just like init does.
	t.Setenv("CRYPTO_BACKEND", "vanilla")
	if v, ok := os.LookupEnv("CRYPTO_BACKEND"); ok {
		if b, parsed := Parse(v); parsed {
			SetDefault(b)
		}
	}
	if got := Default(); got != Vanilla {
		t.Errorf("env override: Default() = %v; want Vanilla", got)
	}
}

func TestEnvOverrideDeprecatedFallback(t *testing.T) {
	// Saved current state.
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	// Ensure neither env is set in the parent shell when this case starts.
	prevNew, hasNew := os.LookupEnv("CRYPTO_BACKEND")
	prevOld, hasOld := os.LookupEnv("LUX_CRYPTO_BACKEND")
	os.Unsetenv("CRYPTO_BACKEND")
	os.Unsetenv("LUX_CRYPTO_BACKEND")
	t.Cleanup(func() {
		if hasNew {
			os.Setenv("CRYPTO_BACKEND", prevNew)
		} else {
			os.Unsetenv("CRYPTO_BACKEND")
		}
		if hasOld {
			os.Setenv("LUX_CRYPTO_BACKEND", prevOld)
		} else {
			os.Unsetenv("LUX_CRYPTO_BACKEND")
		}
	})

	// Deprecated LUX_CRYPTO_BACKEND must still be honored for one transition
	// release.
	t.Setenv("LUX_CRYPTO_BACKEND", "vanilla")
	if v, ok := envBackend(); ok {
		if b, parsed := Parse(v); parsed {
			SetDefault(b)
		}
	}
	if got := Default(); got != Vanilla {
		t.Errorf("deprecated env: Default() = %v; want Vanilla", got)
	}

	// New name wins when both are set.
	t.Setenv("CRYPTO_BACKEND", "cgo")
	if v, ok := envBackend(); ok {
		if b, parsed := Parse(v); parsed {
			SetDefault(b)
		}
	}
	if got := Default(); got != CGo {
		t.Errorf("new name wins: Default() = %v; want CGo", got)
	}
}
