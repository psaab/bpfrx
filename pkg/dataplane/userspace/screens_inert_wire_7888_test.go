package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snapshotForScreenCfg7888 builds the REAL wire snapshot, not the ref builder in
// isolation. That distinction is the point of this file: #7888 exists because
// buildScreenInertProfileRefs was already correct and already had tests, and the
// defect was that nothing carried its output to the helper. A cell that calls
// the builder directly is green on both the broken and the fixed tree.
func snapshotForScreenCfg7888(t *testing.T, lines []string) *ConfigSnapshot {
	t.Helper()
	cfg := compileScreenCfg7059(t, lines)
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return snap
}

// TestScreenInertProfilesReachTheWire_7888 is the wiring guard.
//
// RED on revert: delete `ScreenInertProfiles: buildScreenInertProfileRefs(cfg)`
// from builder.go and the inert row fails — which is exactly the pre-#7888 tree,
// where the set existed, was exported, was rendered by two Go surfaces, and was
// never put on the wire (`grep -c ScreenInert protocol.go` was 0). The helper
// therefore could not tell an inert zone from a zone with no screen at all, and
// gave it a bare Pass.
//
// All THREE states are asserted, and the middle one carries the test. A table of
// only "undefined" and "enforcing" stays green on a tree that collapses inert
// into either of them.
func TestScreenInertProfilesReachTheWire_7888(t *testing.T) {
	for _, tc := range []struct {
		name        string
		lines       []string
		wantInert   []string // zones expected in ScreenInertProfiles
		wantMissing int
		wantScreens int
	}{
		{
			// THE MIDDLE ROW. Passes strict commit with zero warnings, which is
			// what makes it more reachable than an undefined reference.
			name: "defined_but_enables_no_checks_is_carried",
			lines: []string{
				"set security screen ids-option p alarm-without-drop",
				"set security zones security-zone trust screen p",
			},
			wantInert: []string{"trust"}, wantMissing: 0, wantScreens: 0,
		},
		{
			// Defined AND enforcing: a snapshot is published, so there is
			// nothing unresolved to carry. Without this row the field could be
			// populated unconditionally and the inert row would still pass.
			name: "defined_and_enforcing_carries_nothing",
			lines: []string{
				"set security screen ids-option p tcp land",
				"set security zones security-zone trust screen p",
			},
			wantInert: nil, wantMissing: 0, wantScreens: 1,
		},
		{
			// No screen statement at all — a LEGITIMATE silent Pass, and the
			// state the helper must keep distinguishing from the other two.
			// Without this row the inert predicate could be "no snapshot
			// published" and still look correct.
			name: "no_screen_configured_carries_nothing",
			lines: []string{
				"set security zones security-zone trust description plain",
			},
			wantInert: nil, wantMissing: 0, wantScreens: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := snapshotForScreenCfg7888(t, tc.lines)

			got := make([]string, 0, len(snap.ScreenInertProfiles))
			for _, r := range snap.ScreenInertProfiles {
				got = append(got, r.Zone)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantInert, ",") {
				t.Errorf("snapshot.ScreenInertProfiles zones = %v, want %v — the inert "+
					"set must reach the WIRE, not merely be computable (#7888)",
					got, tc.wantInert)
			}
			if len(snap.ScreenMissingProfiles) != tc.wantMissing {
				t.Errorf("snapshot.ScreenMissingProfiles = %d, want %d — the two sets are "+
					"disjoint and must stay separately addressable",
					len(snap.ScreenMissingProfiles), tc.wantMissing)
			}
			if len(snap.Screens) != tc.wantScreens {
				t.Errorf("snapshot.Screens = %d, want %d", len(snap.Screens), tc.wantScreens)
			}
			// The profile name has to travel too: the helper's WARN names it, and
			// a WARN that cannot name the profile sends the operator nowhere.
			for _, r := range snap.ScreenInertProfiles {
				if r.Profile == "" {
					t.Errorf("inert ref for zone %q carries no profile name", r.Zone)
				}
			}
		})
	}
}

// TestScreenInertProfilesWireKeyAndOmitEmpty_7888 pins the two halves of the
// skew contract that live on the GO side.
//
// The JSON key is the wire contract with the Rust decoder — a rename here and a
// matching rename there would keep both suites green while every deployed peer
// silently stopped seeing the field. And `omitempty` is what makes the field
// invisible to an old helper: it must be ABSENT, not `null`, when there is
// nothing to report, so a healthy config's snapshot is byte-identical to what a
// pre-#7888 binary emitted.
func TestScreenInertProfilesWireKeyAndOmitEmpty_7888(t *testing.T) {
	inert := snapshotForScreenCfg7888(t, []string{
		"set security screen ids-option p alarm-without-drop",
		"set security zones security-zone trust screen p",
	})
	blob, err := json.Marshal(inert)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := decoded["screen_inert_profile_zones"]
	if !ok {
		t.Fatalf("wire key %q absent; snapshot keys must match the Rust decoder's "+
			"serde rename exactly", "screen_inert_profile_zones")
	}
	if !strings.Contains(string(raw), `"trust"`) || !strings.Contains(string(raw), `"p"`) {
		t.Errorf("wire value %s must carry both the zone and the profile name", raw)
	}
	// The sibling must be a SEPARATE key, not the same one reused. Merging them
	// is the defect this issue exists to fix, one layer down.
	if _, ok := decoded["screen_missing_profile_zones"]; ok {
		t.Errorf("screen_missing_profile_zones must be ABSENT for an inert-only config; "+
			"the two sets are disjoint and an inert zone is not an undefined one (got %s)",
			decoded["screen_missing_profile_zones"])
	}

	healthy := snapshotForScreenCfg7888(t, []string{
		"set security screen ids-option p tcp land",
		"set security zones security-zone trust screen p",
	})
	hblob, err := json.Marshal(healthy)
	if err != nil {
		t.Fatalf("marshal healthy: %v", err)
	}
	var hdecoded map[string]json.RawMessage
	if err := json.Unmarshal(hblob, &hdecoded); err != nil {
		t.Fatalf("unmarshal healthy: %v", err)
	}
	if _, ok := hdecoded["screen_inert_profile_zones"]; ok {
		t.Errorf("omitempty violated: the key must be ABSENT (not null/[]) when there is " +
			"nothing to report, so an enforcing config's snapshot stays byte-identical to " +
			"what a pre-#7888 binary emitted")
	}
}
