package cli

import (
	"strings"
	"testing"
)

// TestCheckPermission_MonitorTrafficRequiresControl asserts that the
// privileged `monitor traffic` capture (which spawns a root tcpdump) is gated
// behind the control permission: read-only / config-viewer / unauthorized
// classes are DENIED, while operator and super-user are allowed. Reverting the
// #4067 gate (mapping `monitor traffic` back to plain PermView) makes the
// read-only / config-viewer subtests go RED (the capture becomes allowed).
func TestCheckPermission_MonitorTrafficRequiresControl(t *testing.T) {
	tests := []struct {
		class     string
		allowGood bool // monitor traffic allowed?
	}{
		{"super-user", true},
		{"operator", true},
		{"read-only", false},
		{"config-viewer", false},
		{"unauthorized", false},
	}

	for _, tc := range tests {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{userClass: tc.class}

			// monitor traffic (fully spelled) — the privileged capture.
			err := c.checkPermission([]string{"monitor", "traffic", "interface", "ge-0-0-0"})
			if tc.allowGood && err != nil {
				t.Errorf("monitor traffic denied for %q: %v (want allowed)", tc.class, err)
			}
			if !tc.allowGood && err == nil {
				t.Errorf("monitor traffic ALLOWED for %q (want denied — spawns root tcpdump)", tc.class)
			}

			// Abbreviated `monitor tr` must resolve to traffic and be gated
			// identically — the gate must not be bypassable via prefix.
			errAbbrev := c.checkPermission([]string{"monitor", "tr", "interface", "ge-0-0-0"})
			if tc.allowGood && errAbbrev != nil {
				t.Errorf("monitor tr denied for %q: %v (want allowed)", tc.class, errAbbrev)
			}
			if !tc.allowGood && errAbbrev == nil {
				t.Errorf("monitor tr ALLOWED for %q (abbreviation bypassed the gate)", tc.class)
			}
		})
	}
}

// TestCheckPermission_MonitorViewSubcommandsStayViewLevel asserts the gate is
// surgical: read-only can still run the view-level monitor subcommands
// (interface stats, security flow trace) — only the root-tcpdump traffic
// capture is elevated. This guards against over-gating the whole `monitor`
// family.
func TestCheckPermission_MonitorViewSubcommandsStayViewLevel(t *testing.T) {
	c := &CLI{userClass: "read-only"}

	viewOK := [][]string{
		{"monitor", "interface", "ge-0-0-0"},
		{"monitor", "security", "flow"},
		{"monitor"}, // bare monitor (help) stays view-level
	}
	for _, parts := range viewOK {
		if err := c.checkPermission(parts); err != nil {
			t.Errorf("read-only denied %q: %v (want allowed — view-level)", strings.Join(parts, " "), err)
		}
	}
}

// TestCheckPermission_ReadOnlyBaselineUnaffected asserts the change did not
// disturb the existing per-class gating for the other command families.
func TestCheckPermission_ReadOnlyBaselineUnaffected(t *testing.T) {
	readOnly := &CLI{userClass: "read-only"}

	// show / ping / traceroute remain allowed (view).
	for _, cmd := range [][]string{{"show", "version"}, {"ping", "1.1.1.1"}, {"traceroute", "1.1.1.1"}} {
		if err := readOnly.checkPermission(cmd); err != nil {
			t.Errorf("read-only denied view command %q: %v", strings.Join(cmd, " "), err)
		}
	}
	// clear / request / configure remain denied for read-only.
	for _, cmd := range [][]string{{"clear", "security", "flow", "session"}, {"request", "system", "reboot"}, {"configure"}} {
		if err := readOnly.checkPermission(cmd); err == nil {
			t.Errorf("read-only ALLOWED elevated command %q (want denied)", strings.Join(cmd, " "))
		}
	}

	// Unset class keeps the legacy allow-everything behavior.
	unset := &CLI{userClass: ""}
	if err := unset.checkPermission([]string{"monitor", "traffic", "interface", "ge-0-0-0"}); err != nil {
		t.Errorf("unset class denied monitor traffic: %v (want allowed — legacy no-RBAC)", err)
	}
}
