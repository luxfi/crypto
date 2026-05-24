// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import (
	"testing"
)

func TestFallbackReasonString(t *testing.T) {
	cases := map[FallbackReason]string{
		FallbackDisabled:           "disabled",
		FallbackUnsupported:        "unsupported",
		FallbackProbeFailed:        "probe_failed",
		FallbackBackendUnavailable: "backend_unavailable",
		FallbackABIMismatch:        "abi_mismatch",
		FallbackReason(99):         "unknown",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("FallbackReason(%d).String() = %q; want %q", r, got, want)
		}
	}
}

func TestRecordFallbackIncrements(t *testing.T) {
	resetFallbackForTest()
	t.Cleanup(resetFallbackForTest)

	RecordFallback(FallbackDisabled, "amm")
	RecordFallback(FallbackDisabled, "amm")
	RecordFallback(FallbackUnsupported, "clob")

	c := FallbackCounters()
	if c["disabled"] != 2 {
		t.Errorf("disabled counter = %d; want 2", c["disabled"])
	}
	if c["unsupported"] != 1 {
		t.Errorf("unsupported counter = %d; want 1", c["unsupported"])
	}
	if c["probe_failed"] != 0 {
		t.Errorf("probe_failed counter = %d; want 0", c["probe_failed"])
	}
}

func TestRecordFallbackKeysAreLowCardinality(t *testing.T) {
	resetFallbackForTest()
	t.Cleanup(resetFallbackForTest)

	// Even a million RecordFallback calls only ever land in five keys.
	for i := 0; i < 1000; i++ {
		RecordFallback(FallbackDisabled, "amm")
		RecordFallback(FallbackUnsupported, "clob")
		RecordFallback(FallbackProbeFailed, "fhe_ntt")
		RecordFallback(FallbackBackendUnavailable, "amm")
		RecordFallback(FallbackABIMismatch, "clob")
	}
	c := FallbackCounters()
	if len(c) != int(numFallbackReasons) {
		t.Fatalf("counter key set drifted: %d keys; want %d", len(c), numFallbackReasons)
	}
	for _, want := range []string{"disabled", "unsupported", "probe_failed", "backend_unavailable", "abi_mismatch"} {
		if c[want] == 0 {
			t.Errorf("expected non-zero count for %q", want)
		}
	}
}

func TestRecordFallbackOutOfRangeIsNoop(t *testing.T) {
	resetFallbackForTest()
	t.Cleanup(resetFallbackForTest)

	RecordFallback(FallbackReason(99), "amm")
	for k, v := range FallbackCounters() {
		if v != 0 {
			t.Errorf("counter %q got %d after out-of-range call; want 0", k, v)
		}
	}
}

func TestProbeSurfacesDisabledAndFallbacks(t *testing.T) {
	resetFallbackForTest()
	t.Cleanup(resetFallbackForTest)

	RecordFallback(FallbackUnsupported, "amm")

	p := Probe()
	if p.Disabled != GPUDisabled() {
		t.Errorf("Probe.Disabled=%v != GPUDisabled()=%v", p.Disabled, GPUDisabled())
	}
	if p.Fallbacks["unsupported"] != 1 {
		t.Errorf("Probe.Fallbacks[unsupported]=%d; want 1", p.Fallbacks["unsupported"])
	}
	s := p.String()
	if len(s) == 0 || s[0] != 'b' {
		t.Errorf("Probe.String prefix wrong: %q", s)
	}
}
