// #7016: the premise every surface-level guard in this fix rests on — that the
// WARM-UP window really does produce ErrPolicyCounterUnpublished from the
// PRODUCTION objects, not just from a test fake.
//
// `Server.dp.IsLoaded()` goes true as soon as the shim is loaded, which happens
// BEFORE the first 1 Hz control-socket status poll populates m.lastStatus. In
// that window the bulk snapshot is empty, so every counter-eligible policy
// resolves to the unpublished signal. The observability surfaces used to turn
// that into a whole-response failure (REST 500 / gRPC codes.Internal); they now
// flag the affected rules instead. This test pins the input side of that.
package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestWarmUpBulkSnapshotIsEmptyAndReadsUnpublished drives the REAL Manager and
// the REAL LegacyDataPlaneAdapter (the object the daemon publishes) in the
// pre-first-status-poll state.
//
// FAIL-ON-REVERT: this documents behaviour the fix does NOT change — it is the
// premise, so it is green before and after. Its job is to fail if a later change
// makes warm-up return something OTHER than the unpublished signal (a silent
// zero, say), which would quietly void the per-rule flag the surfaces now set.
func TestWarmUpBulkSnapshotIsEmptyAndReadsUnpublished(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			PolicyStatsEnabled: true,
			Policies: []*config.ZonePairPolicies{{
				FromZone: "lan",
				ToZone:   "wan",
				Policies: []*config.Policy{{Name: "allow-web"}},
			}},
			GlobalPolicies: []*config.Policy{{Name: "global-allow"}},
		},
	}

	// New() leaves lastStatus zero-valued: no status poll has landed yet.
	m := New()
	adapter := NewLegacyDataPlaneAdapter(m)

	all, err := adapter.ReadAllPolicyCounters(cfg)
	if err != nil {
		t.Fatalf("ReadAllPolicyCounters in warm-up returned an error (%v); the bulk read must succeed with an EMPTY snapshot, not fail", err)
	}
	if len(all) != 0 {
		t.Fatalf("warm-up bulk snapshot has %d entries, want 0 (no status poll has landed)", len(all))
	}

	// The fallback must NOT run: the adapter carries ReadAllPolicyCounters, so
	// the bulk probe resolves and the closure answers from the empty snapshot.
	fallbackRan := false
	read := NewPolicyCounterReader(adapter, cfg, func(uint32) (dataplane.CounterValue, error) {
		fallbackRan = true
		return dataplane.CounterValue{Packets: 99}, nil
	})

	for _, tc := range []struct {
		name   string
		handle uint32
	}{
		{"zone-pair rule", 0},
		{"global rule", dataplane.MaxRulesPerPolicy},
		{"implicit default policy", dataplane.DefaultPolicySentinelID},
	} {
		v, err := read(tc.handle)
		if !errors.Is(err, ErrPolicyCounterUnpublished) {
			t.Errorf("%s (handle %d): err = %v, want ErrPolicyCounterUnpublished", tc.name, tc.handle, err)
		}
		if v != (dataplane.CounterValue{}) {
			t.Errorf("%s (handle %d): value = %+v, want the zero value alongside the unpublished signal", tc.name, tc.handle, v)
		}
	}
	if fallbackRan {
		t.Error("the per-policy fallback ran; the adapter provides ReadAllPolicyCounters so the bulk probe must resolve (#6743 r7-N2)")
	}
}
