package flowexport

import (
	"math"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6769 — a flow-export template `seconds` knob large enough to overflow
// `time.Duration(n) * time.Second` used to WRAP into a sub-second interval.
//
// The three knobs (`template-refresh-rate seconds`, `flow-active-timeout`,
// `flow-inactive-timeout`) are stored by the compiler as a plain int from
// `strconv.Atoi`. This package then computed `time.Duration(n) * time.Second`.
// int64 nanoseconds overflow past math.MaxInt64/1e9 = 9223372036 seconds, and
// the wrapped product can be small and POSITIVE — the dangerous half, because
// `templateRefreshInterval` only rejects `<= 0`, so `time.NewTicker` happily
// fires on it and the exporter re-emits its templates thousands of times a
// second at every collector.
//
// gcd(1e9, 2^64) = 512, so wrapped residues are multiples of 512ns and the
// smallest positive one is exactly 512ns. overflowSeconds below is the value
// that produces it.
const overflowSeconds = 20211507185753197

// TestOverflowFixtureActuallyWraps_6769 is the non-vacuity guard for every
// other cell in this file: it proves the fixture value is a REAL overflow that
// lands positive and sub-second, not merely a large number. If someone edits
// overflowSeconds to something that no longer wraps, the range-check cells
// below would still pass while testing nothing — this cell fails instead.
func TestOverflowFixtureActuallyWraps_6769(t *testing.T) {
	if overflowSeconds <= config.MaxDurationSeconds {
		t.Fatalf("fixture %d is within MaxDurationSeconds (%d); it cannot overflow and the "+
			"other cells in this file would be vacuous", overflowSeconds, config.MaxDurationSeconds)
	}
	// Via a variable, not a constant expression: Go rejects the constant form at
	// compile time. That is itself part of the story — the value only reaches
	// this multiply at RUNTIME, as an int the compiler read with strconv.Atoi,
	// which is precisely why nothing caught it.
	n := overflowSeconds
	wrapped := time.Duration(n) * time.Second
	if wrapped <= 0 {
		t.Fatalf("fixture wraps to %v; the cells here guard the POSITIVE wrap (the one "+
			"templateRefreshInterval's `<= 0` check does not catch)", wrapped)
	}
	if wrapped >= time.Second {
		t.Fatalf("fixture wraps to %v, not a sub-second interval; pick a value whose residue "+
			"is small or the flood scenario is not reproduced", wrapped)
	}
	if wrapped != 512*time.Nanosecond {
		t.Errorf("fixture wraps to %v, want 512ns (gcd(1e9, 2^64) = 512)", wrapped)
	}
	if config.MaxDurationSeconds != int64(math.MaxInt64)/int64(time.Second) {
		t.Errorf("MaxDurationSeconds = %d, want math.MaxInt64/1e9 — the ceiling must stay the "+
			"runtime-derived overflow point, not a policy cap", config.MaxDurationSeconds)
	}
}

// TestV9TemplateContextRejectsOverflowSeconds_6769: all three v9 knobs fall
// back to their defaults for an out-of-range value. Reverting secondsToDuration
// to `if n > 0 { d = time.Duration(n) * time.Second }` makes each of these 512ns.
func TestV9TemplateContextRejectsOverflowSeconds_6769(t *testing.T) {
	tc := v9TemplateContext(&config.NetFlowV9Template{
		TemplateRefreshRate: overflowSeconds,
		FlowActiveTimeout:   overflowSeconds,
		FlowInactiveTimeout: overflowSeconds,
	})
	if tc.refreshRate != 60*time.Second {
		t.Errorf("refreshRate = %v, want 60s (out-of-range value must fall back to the default)", tc.refreshRate)
	}
	if tc.activeTimeout != 60*time.Second {
		t.Errorf("activeTimeout = %v, want 60s", tc.activeTimeout)
	}
	if tc.inactiveTimeout != 15*time.Second {
		t.Errorf("inactiveTimeout = %v, want 15s", tc.inactiveTimeout)
	}
}

// TestIPFIXTemplateContextRejectsOverflowSeconds_6769 is the IPFIX arm. Both
// template families carry an independent copy of the conversion, so a fix
// applied to only one of them leaves the other wrapping.
func TestIPFIXTemplateContextRejectsOverflowSeconds_6769(t *testing.T) {
	tc := ipfixTemplateContext(&config.NetFlowIPFIXTemplate{
		TemplateRefreshRate: overflowSeconds,
		FlowActiveTimeout:   overflowSeconds,
		FlowInactiveTimeout: overflowSeconds,
	})
	if tc.refreshRate != 60*time.Second {
		t.Errorf("refreshRate = %v, want 60s", tc.refreshRate)
	}
	if tc.activeTimeout != 60*time.Second {
		t.Errorf("activeTimeout = %v, want 60s", tc.activeTimeout)
	}
	if tc.inactiveTimeout != 15*time.Second {
		t.Errorf("inactiveTimeout = %v, want 15s", tc.inactiveTimeout)
	}
}

// TestSaneTemplateSecondsUnchanged_6769 is the negative control: an ordinary
// configuration must be converted exactly as before. A "fix" that clamped
// everything, or that fell back on any non-default value, fails here.
func TestSaneTemplateSecondsUnchanged_6769(t *testing.T) {
	tc := v9TemplateContext(&config.NetFlowV9Template{
		TemplateRefreshRate: 300,
		FlowActiveTimeout:   120,
		FlowInactiveTimeout: 30,
	})
	if tc.refreshRate != 300*time.Second {
		t.Errorf("refreshRate = %v, want 300s (a valid value must pass through unchanged)", tc.refreshRate)
	}
	if tc.activeTimeout != 120*time.Second {
		t.Errorf("activeTimeout = %v, want 120s", tc.activeTimeout)
	}
	if tc.inactiveTimeout != 30*time.Second {
		t.Errorf("inactiveTimeout = %v, want 30s", tc.inactiveTimeout)
	}
	// The boundary itself is in range and must NOT be rejected.
	tcMax := v9TemplateContext(&config.NetFlowV9Template{TemplateRefreshRate: int(config.MaxDurationSeconds)})
	if tcMax.refreshRate != time.Duration(config.MaxDurationSeconds)*time.Second {
		t.Errorf("refreshRate at the ceiling = %v, want the converted ceiling; the bound is "+
			"inclusive because that value does not overflow", tcMax.refreshRate)
	}
}

// TestResolveV9TemplateGroupsDoesNotShipAWrappedRefresh_6769 binds the WIRING:
// it drives the production resolver a manager uses to build ExportConfigs, so
// deleting the secondsToDuration call from v9TemplateContext (rather than
// breaking secondsToDuration itself) reds here.
//
// The tolerant load / peer-sync path is exactly how such a value reaches this
// code in practice: strict commit now rejects it, but an already-persisted or
// peer-synced config authored by a pre-guard version is admitted with a warning
// (#1960), and the running exporter must still be safe.
func TestResolveV9TemplateGroupsDoesNotShipAWrappedRefresh_6769(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"poisoned": {Name: "poisoned", TemplateRefreshRate: overflowSeconds},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"alpha": {
					Name:      "alpha",
					InputRate: 1,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{{
							Address:          "10.0.0.1",
							Port:             2055,
							Version:          config.FlowServerVersion9,
							Version9Template: "poisoned",
						}},
					},
				},
			},
		},
	}
	groups := ResolveV9TemplateGroups(svc, fo)
	if len(groups) != 1 {
		t.Fatalf("got %d export groups, want 1", len(groups))
	}
	got := groups[0].TemplateRefreshRate
	if got != 60*time.Second {
		t.Fatalf("shipped TemplateRefreshRate = %v, want 60s; a sub-second refresh floods the "+
			"collector with template re-exports", got)
	}
	// And the value the exporter's ticker would actually use.
	if eff := templateRefreshInterval(got); eff < time.Second {
		t.Errorf("effective ticker interval = %v (sub-second)", eff)
	}
}
