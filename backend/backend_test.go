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

func TestCGoAvailableMatchesBuildTag(t *testing.T) {
	// cgoLinked is a compile-time constant; CGoAvailable is its accessor.
	// On a cgo build the value is true, on a no-cgo build it is false.
	// Either way, repeated calls must return the same value.
	v1 := CGoAvailable()
	v2 := CGoAvailable()
	if v1 != v2 {
		t.Fatalf("CGoAvailable() not stable: %v then %v", v1, v2)
	}
}

func TestGPUAvailableStable(t *testing.T) {
	// GPUAvailable goes through gpuhost.Available which caches the
	// result of a single accel.Init. Two consecutive calls must agree.
	v1 := GPUAvailable()
	v2 := GPUAvailable()
	if v1 != v2 {
		t.Fatalf("GPUAvailable() not stable: %v then %v", v1, v2)
	}
}

func TestAvailableMatchesProbes(t *testing.T) {
	if !Available(Auto) || !Available(Vanilla) {
		t.Fatal("Auto and Vanilla must always be available")
	}
	if Available(CGo) != CGoAvailable() {
		t.Errorf("Available(CGo)=%v differs from CGoAvailable()=%v",
			Available(CGo), CGoAvailable())
	}
	if Available(GPU) != GPUAvailable() {
		t.Errorf("Available(GPU)=%v differs from GPUAvailable()=%v",
			Available(GPU), GPUAvailable())
	}
}

func TestResolvedMatchesResolve(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	for _, d := range []Backend{Auto, Vanilla, CGo, GPU} {
		SetDefault(d)
		want := Resolve(GPUAvailable(), CGoAvailable())
		got := Resolved()
		if got != want {
			t.Errorf("Resolved() with Default=%s = %s; want %s", d, got, want)
		}
	}
}

func TestIsHelpersMatchResolved(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	for _, d := range []Backend{Auto, Vanilla, CGo, GPU} {
		SetDefault(d)
		r := Resolved()
		if IsGPU() != (r == GPU) {
			t.Errorf("IsGPU mismatch under default=%s: IsGPU=%v Resolved=%s", d, IsGPU(), r)
		}
		if IsCGo() != (r == CGo) {
			t.Errorf("IsCGo mismatch under default=%s: IsCGo=%v Resolved=%s", d, IsCGo(), r)
		}
		if IsVanilla() != (r == Vanilla) {
			t.Errorf("IsVanilla mismatch under default=%s: IsVanilla=%v Resolved=%s", d, IsVanilla(), r)
		}
	}
}

func TestProbeIsConsistentWithHelpers(t *testing.T) {
	t.Cleanup(func() { SetDefault(Auto) })
	SetDefault(Vanilla)
	p := Probe()
	if p.Default != Default() {
		t.Errorf("Probe.Default=%s != Default()=%s", p.Default, Default())
	}
	if p.Resolved != Resolved() {
		t.Errorf("Probe.Resolved=%s != Resolved()=%s", p.Resolved, Resolved())
	}
	if p.CGo != CGoAvailable() {
		t.Errorf("Probe.CGo=%v != CGoAvailable()=%v", p.CGo, CGoAvailable())
	}
	if p.GPU != GPUAvailable() {
		t.Errorf("Probe.GPU=%v != GPUAvailable()=%v", p.GPU, GPUAvailable())
	}
	s := p.String()
	if len(s) == 0 || s[0] != 'b' {
		t.Errorf("Snapshot.String() = %q; want prefix 'backend{...}'", s)
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

