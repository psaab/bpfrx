package config

import (
	"math"
	"strings"
	"testing"
)

// Copilot #4320 FIX 2/3: validateClassOfServiceStrict must reject a NON-FINITE
// percent. NaN compares false to both range bounds, so a bare `< 0 || > 100`
// check let a constructed / peer-synced / rollback config smuggle a NaN percent
// through. These tests construct the typed struct directly (the schema gate is
// bypassed on the Load / HA SyncApply path) and assert the strict validator
// fails closed. RED on revert: without the math.IsNaN guard the NaN cases pass.

func TestValidateClassOfServiceStrict_TransmitRatePercentNaN_Rejected(t *testing.T) {
	cos := &ClassOfServiceConfig{
		Schedulers: map[string]*CoSScheduler{
			"be": {Name: "be", TransmitRatePercent: math.NaN()},
		},
	}
	err := validateClassOfServiceStrict(cos)
	if err == nil {
		t.Fatal("expected NaN transmit-rate percent to be rejected")
	}
	if !strings.Contains(err.Error(), "transmit-rate percent") {
		t.Fatalf("error should reference transmit-rate percent: %v", err)
	}
}

func TestValidateClassOfServiceStrict_TransmitRatePercentInf_Rejected(t *testing.T) {
	cos := &ClassOfServiceConfig{
		Schedulers: map[string]*CoSScheduler{
			"be": {Name: "be", TransmitRatePercent: math.Inf(1)},
		},
	}
	if err := validateClassOfServiceStrict(cos); err == nil {
		t.Fatal("expected +Inf transmit-rate percent to be rejected")
	}
}

func TestValidateClassOfServiceStrict_ShapingRatePercentNaN_Rejected(t *testing.T) {
	cos := &ClassOfServiceConfig{
		TrafficControlProfiles: map[string]*CoSTrafficControlProfile{
			"p1": {Name: "p1", ShapingRatePercent: math.NaN()},
		},
	}
	err := validateClassOfServiceStrict(cos)
	if err == nil {
		t.Fatal("expected NaN shaping-rate percent to be rejected")
	}
	if !strings.Contains(err.Error(), "shaping-rate percent") {
		t.Fatalf("error should reference shaping-rate percent: %v", err)
	}
}

// A finite in-range percent constructed struct still validates (guard is scoped
// to non-finite / out-of-range, not a blanket reject).
func TestValidateClassOfServiceStrict_FinitePercent_Accepted(t *testing.T) {
	cos := &ClassOfServiceConfig{
		Schedulers: map[string]*CoSScheduler{
			"be": {Name: "be", TransmitRatePercent: 50},
		},
		TrafficControlProfiles: map[string]*CoSTrafficControlProfile{
			"p1": {Name: "p1", ShapingRatePercent: 90},
		},
	}
	if err := validateClassOfServiceStrict(cos); err != nil {
		t.Fatalf("finite in-range percent wrongly rejected: %v", err)
	}
}
