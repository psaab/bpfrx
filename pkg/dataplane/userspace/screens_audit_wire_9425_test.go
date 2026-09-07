package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestInertProfileAuditFlagReachesTheWire_9425 is the wiring guard for member 1.
//
// The Rust side can only honour an inert zone's `alarm-without-drop` if the flag
// TRAVELS. An inert zone gets no `screens` entry, so the resolved
// ScreenProfileSnapshot.AlarmWithoutDrop that the enforcing case rides on is
// never emitted for it — the ONLY channel is ScreenInertProfileRefs.
//
// This asserts on the real JSON, not the Go struct: struct -> wire is a second
// hop, and the field is `omitempty`, so a mis-tagged field would still satisfy
// a struct-level assertion while emitting nothing.
//
// RED on revert: drop `AlarmWithoutDrop:` from buildScreenInertProfileRefs and
// the audit row loses the key.
func TestInertProfileAuditFlagReachesTheWire_9425(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lines     []string
		wantAudit bool
	}{
		{
			// The canonical route into the inert state, and an explicit request
			// for audit mode. `docs/feature-coverage.md` records that this
			// passes STRICT commit with zero warnings.
			name: "alarm_without_drop_only_carries_the_flag",
			lines: []string{
				"set security screen ids-option p alarm-without-drop",
				"set security zones security-zone trust screen p",
			},
			wantAudit: true,
		},
		{
			// CONTROL. Also inert (a bare threshold modifier enables no check),
			// but the operator did NOT ask for audit mode, so the flag must be
			// absent and #7888's hard-drop posture must survive. Without this
			// row an unconditional `true` passes the row above.
			name: "inert_without_the_modifier_carries_no_flag",
			lines: []string{
				"set security screen ids-option p",
				"set security zones security-zone trust screen p",
			},
			wantAudit: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := snapshotForScreenCfg7888(t, tc.lines)
			if len(snap.ScreenInertProfiles) != 1 {
				t.Fatalf("POSITIVE CONTROL: expected exactly one inert ref (the zone "+
					"must actually BE inert, or the flag assertion below is vacuous), "+
					"got %+v", snap.ScreenInertProfiles)
			}
			if got := snap.ScreenInertProfiles[0].AlarmWithoutDrop; got != tc.wantAudit {
				t.Errorf("ScreenInertProfiles[0].AlarmWithoutDrop = %v, want %v", got, tc.wantAudit)
			}

			b, err := json.Marshal(snap.ScreenInertProfiles[0])
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			hasKey := strings.Contains(string(b), `"alarm_without_drop":true`)
			if hasKey != tc.wantAudit {
				t.Errorf("wire JSON %s: alarm_without_drop:true present = %v, want %v",
					b, hasKey, tc.wantAudit)
			}
		})
	}
}

// TestUndefinedProfileRefCarriesNoAuditFlag_9425 is the shared-struct control.
//
// ScreenMissingProfileRef backs BOTH wire sets. On the UNDEFINED set there is no
// profile to read the modifier from, so the flag must stay false there — a
// builder that filled it from somewhere else would let the undefined set inherit
// the inert set's meaning through a struct they happen to share.
func TestUndefinedProfileRefCarriesNoAuditFlag_9425(t *testing.T) {
	// The UNDEFINED state is strict-REJECTED, so it can only be built on the
	// tolerant path (HA config-sync from a schema-skewed peer, tolerant load of
	// an older active.json) — which is the only path that reaches it in
	// production too.
	cfg := compileScreenCfgLenient7059(t, []string{
		"set security zones security-zone trust screen ghost",
	})
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.ScreenMissingProfiles) != 1 {
		t.Fatalf("POSITIVE CONTROL: expected exactly one undefined ref, got %+v",
			snap.ScreenMissingProfiles)
	}
	if snap.ScreenMissingProfiles[0].AlarmWithoutDrop {
		t.Error("an UNDEFINED profile reference must never carry an audit flag: there " +
			"is no profile that could have declared it, so there is no operator " +
			"statement for the dataplane to honour")
	}
}
