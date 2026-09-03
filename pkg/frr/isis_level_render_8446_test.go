package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderISISLevel(t *testing.T, level string) string {
	t.Helper()
	m := &Manager{}
	got := m.generateProtocols(nil, nil, nil, nil,
		&config.ISISConfig{NET: "49.0001.1921.6800.1001.00", Level: level}, "", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") {
		t.Fatalf("Level=%q: render did not reach the IS-IS block at all", level)
	}
	for _, ln := range strings.Split(got, "\n") {
		if strings.Contains(ln, "is-type") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// #8446. The switch on ISISConfig.Level had no `default` arm, so a value
// outside the three it named emitted NOTHING and FRR silently applied its own
// default, level-1-2. This asserts the property that failed: an is-type line is
// ALWAYS emitted.
//
// Note the shape: it varies the axis across values the old code handled AND
// values it did not. A table that samples only the three handled values passes
// against the defect — which is why frr_test.go's single `level-1-2` case never
// saw it.
func TestISISRenderAlwaysEmitsIsType_8446(t *testing.T) {
	for _, level := range []string{
		"level-1", "level-2", "level-1-2", // handled before the fix
		"level-2-only", // the renderer's OWN output spelling
		"", "1", "2", "level 2", "LEVEL-2", "level-3", "garbage",
	} {
		if got := renderISISLevel(t, level); got == "" {
			t.Errorf("Level=%q emitted NO is-type line — FRR falls back to level-1-2 (the #8446 widening)", level)
		}
	}
}

// The direction of the failure is what matters: an unrecognized value must
// never render WIDER than the narrow default. Narrower is a recoverable
// misconfiguration; wider is a silent security regression.
func TestISISRenderNeverWidensOnUnrecognized_8446(t *testing.T) {
	for _, level := range []string{"1", "2", "level 2", "LEVEL-2", "level-3", "garbage", "level-2-only"} {
		got := renderISISLevel(t, level)
		if strings.Contains(got, "level-1-2") {
			t.Errorf("Level=%q rendered %q — WIDER than the narrow default", level, got)
		}
	}
	// Positive control: level-1-2 is still reachable when it is what was
	// AUTHORED, so the assertion above is not passing by making it unreachable.
	if got := renderISISLevel(t, "level-1-2"); !strings.Contains(got, "level-1-2") {
		t.Errorf("authored level-1-2 rendered %q — the fix has made a valid level unreachable", got)
	}
}

// Round trip: the string this renderer EMITS must survive being fed back in.
// That round trip is what made #8446 sharp, and it is the cheapest cell to
// keep honest — it reads the renderer's own output rather than a literal.
func TestISISRenderOutputRoundTrips_8446(t *testing.T) {
	for _, authored := range []string{"level-1", "level-2", "level-1-2", ""} {
		emitted := renderISISLevel(t, authored)
		// " is-type level-2-only" -> "level-2-only"
		fields := strings.Fields(emitted)
		if len(fields) != 2 {
			t.Fatalf("authored %q: unexpected is-type line %q", authored, emitted)
		}
		fedBack := renderISISLevel(t, fields[1])
		if fedBack != emitted {
			t.Errorf("authored %q emitted %q; feeding %q back emitted %q — not a fixed point",
				authored, emitted, fields[1], fedBack)
		}
	}
}
