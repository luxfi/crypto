// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import "testing"

func TestProvenance_NonEmpty(t *testing.T) {
	p := GetProvenance()
	if p.Tier == TierUnknown {
		t.Fatal("GetProvenance returned TierUnknown — dispatcher cannot determine its own state")
	}
	if p.BatchThresholdN <= 0 {
		t.Errorf("BatchThresholdN = %d", p.BatchThresholdN)
	}
	if p.ConcurrentThresholdN <= 0 {
		t.Errorf("ConcurrentThresholdN = %d", p.ConcurrentThresholdN)
	}
	t.Logf("ML-DSA dispatch provenance: tier=%s accel=%v device=%v plugin_strong=%v batch_threshold=%d concurrent_threshold=%d",
		p.Tier, p.AccelInitialised, p.DeviceAvailable, p.PluginStrongSymbol,
		p.BatchThresholdN, p.ConcurrentThresholdN)
}

func TestProvenance_NoFalseGPUClaim(t *testing.T) {
	p := GetProvenance()
	if p.Tier == TierGPUSubstrate && !p.PluginStrongSymbol {
		t.Fatalf("Provenance reports TierGPUSubstrate but PluginStrongSymbol=false — false GPU claim")
	}
}
