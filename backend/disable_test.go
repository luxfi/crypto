// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import "testing"

func TestParseTruthy(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"0":     false,
		"false": false,
		"FALSE": false,
		"no":    false,
		"NO":    false,
		"off":   false,
		" 0 ":   false,
		"1":     true,
		"true":  true,
		"yes":   true,
		"on":    true,
		"YES":   true,
		"foo":   true, // any non-falsy spelling counts as truthy
	}
	for in, want := range cases {
		if got := parseTruthy(in); got != want {
			t.Errorf("parseTruthy(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestGPUDisabledStable(t *testing.T) {
	// gpuDisabled is parsed once at init; repeated calls must agree.
	v1 := GPUDisabled()
	v2 := GPUDisabled()
	if v1 != v2 {
		t.Fatalf("GPUDisabled() not stable: %v then %v", v1, v2)
	}
}

func TestGPUAvailableHonorsDisabled(t *testing.T) {
	// When disabled, GPUAvailable must return false regardless of probe.
	if GPUDisabled() && GPUAvailable() {
		t.Fatal("GPUAvailable=true while GPUDisabled=true — kill switch ignored")
	}
}
