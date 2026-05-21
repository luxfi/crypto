// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"testing"
)

// TestProvenance_NonEmpty is a smoke test that pins the API: a release
// binary MUST be able to introspect its own dispatch tier without an
// error path or panic. This is the function a release reviewer or CI
// gate calls to confirm that the "GPU accelerated SLH-DSA" claim is
// not vapor.
func TestProvenance_NonEmpty(t *testing.T) {
	p := GetProvenance()
	if p.Tier == TierUnknown {
		t.Fatal("GetProvenance returned TierUnknown — dispatcher cannot determine its own state")
	}
	if p.SignBatchThresholdN <= 0 {
		t.Errorf("SignBatchThresholdN = %d (expected positive)", p.SignBatchThresholdN)
	}
	if p.ConcurrentSignThresholdN <= 0 {
		t.Errorf("ConcurrentSignThresholdN = %d (expected positive)", p.ConcurrentSignThresholdN)
	}
	t.Logf("SLH-DSA dispatch provenance: tier=%s accel=%v device=%v plugin_strong=%v sign_threshold=%d concurrent_threshold=%d",
		p.Tier, p.AccelInitialised, p.DeviceAvailable, p.PluginStrongSymbol,
		p.SignBatchThresholdN, p.ConcurrentSignThresholdN)
}

// TestProvenance_TierFlowsToCPUWhenNoPlugin pins the contract: when
// the SLH-DSA backend plugin is not loaded (which is the case for the
// in-tree default build), GetProvenance MUST report a CPU tier and NOT
// claim GPU. This is the test that protects against a future
// regression where someone defaults TierGPUSubstrate as the "happy
// path" without verifying plugin load.
func TestProvenance_TierFlowsToCPUWhenNoPlugin(t *testing.T) {
	p := GetProvenance()
	if p.Tier == TierGPUSubstrate && !p.PluginStrongSymbol {
		t.Fatalf("Provenance reported TierGPUSubstrate without PluginStrongSymbol — false GPU claim")
	}
	// The default build does NOT ship a plugin. Whichever CPU tier we
	// land on (accel-cpu-fallback when accel init succeeded, goroutine-
	// parallel-cpu when it did not), the binary is honest about it.
	switch p.Tier {
	case TierGPUSubstrate, TierAccelCPUFallback, TierGoroutineParallelCPU, TierSerialCPU:
		// OK — any one of these is a truthful tier.
	default:
		t.Fatalf("unexpected tier %v (%d)", p.Tier, p.Tier)
	}
}
