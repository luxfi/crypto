// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"testing"
)

func TestSchemeIDString(t *testing.T) {
	tests := []struct {
		id       SchemeID
		expected string
	}{
		{SchemeUnknown, "Unknown"},
		{SchemeFROST, "FROST"},
		{SchemeCMP, "CMP"},
		{SchemeBLS, "BLS"},
		{SchemeRingtail, "Ringtail"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.id.String(); got != tc.expected {
				t.Errorf("SchemeID.String() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestSchemeIDPostQuantum(t *testing.T) {
	tests := []struct {
		id       SchemeID
		expected bool
	}{
		{SchemeUnknown, false},
		{SchemeFROST, false},
		{SchemeCMP, false},
		{SchemeBLS, false},
		{SchemeRingtail, true},
	}

	for _, tc := range tests {
		t.Run(tc.id.String(), func(t *testing.T) {
			if got := tc.id.IsPostQuantum(); got != tc.expected {
				t.Errorf("SchemeID.IsPostQuantum() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestSchemeIDNonInteractive(t *testing.T) {
	tests := []struct {
		id       SchemeID
		expected bool
	}{
		{SchemeUnknown, false},
		{SchemeFROST, false},
		{SchemeCMP, false},
		{SchemeBLS, true},
		{SchemeRingtail, false},
	}

	for _, tc := range tests {
		t.Run(tc.id.String(), func(t *testing.T) {
			if got := tc.id.SupportsNonInteractive(); got != tc.expected {
				t.Errorf("SchemeID.SupportsNonInteractive() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestDKGConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  DKGConfig
		wantErr error
	}{
		{
			name: "valid 2-of-3",
			config: DKGConfig{
				Threshold:    1,
				TotalParties: 3,
				PartyIndex:   0,
			},
			wantErr: nil,
		},
		{
			name: "valid 3-of-5",
			config: DKGConfig{
				Threshold:    2,
				TotalParties: 5,
				PartyIndex:   4,
			},
			wantErr: nil,
		},
		{
			name: "zero threshold",
			config: DKGConfig{
				Threshold:    0,
				TotalParties: 3,
				PartyIndex:   0,
			},
			wantErr: ErrInvalidThreshold,
		},
		{
			name: "single party",
			config: DKGConfig{
				Threshold:    0,
				TotalParties: 1,
				PartyIndex:   0,
			},
			wantErr: ErrInvalidThreshold,
		},
		{
			name: "threshold equals total",
			config: DKGConfig{
				Threshold:    3,
				TotalParties: 3,
				PartyIndex:   0,
			},
			wantErr: ErrThresholdTooHigh,
		},
		{
			name: "threshold exceeds total",
			config: DKGConfig{
				Threshold:    4,
				TotalParties: 3,
				PartyIndex:   0,
			},
			wantErr: ErrThresholdTooHigh,
		},
		{
			name: "negative party index",
			config: DKGConfig{
				Threshold:    1,
				TotalParties: 3,
				PartyIndex:   -1,
			},
			wantErr: ErrInvalidPartyIndex,
		},
		{
			name: "party index too high",
			config: DKGConfig{
				Threshold:    1,
				TotalParties: 3,
				PartyIndex:   3,
			},
			wantErr: ErrInvalidPartyIndex,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if err != tc.wantErr {
				t.Errorf("DKGConfig.Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDealerConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  DealerConfig
		wantErr error
	}{
		{
			name: "valid 2-of-3",
			config: DealerConfig{
				Threshold:    1,
				TotalParties: 3,
			},
			wantErr: nil,
		},
		{
			name: "valid 5-of-10",
			config: DealerConfig{
				Threshold:    4,
				TotalParties: 10,
			},
			wantErr: nil,
		},
		{
			name: "zero threshold",
			config: DealerConfig{
				Threshold:    0,
				TotalParties: 3,
			},
			wantErr: ErrInvalidThreshold,
		},
		{
			name: "threshold equals total",
			config: DealerConfig{
				Threshold:    3,
				TotalParties: 3,
			},
			wantErr: ErrThresholdTooHigh,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if err != tc.wantErr {
				t.Errorf("DealerConfig.Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state    SessionState
		expected string
	}{
		{SessionStateNew, "New"},
		{SessionStateNonceGeneration, "NonceGeneration"},
		{SessionStateSigning, "Signing"},
		{SessionStateAggregating, "Aggregating"},
		{SessionStateComplete, "Complete"},
		{SessionStateFailed, "Failed"},
		{SessionState(99), "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.state.String(); got != tc.expected {
				t.Errorf("SessionState.String() = %v, want %v", got, tc.expected)
			}
		})
	}
}
