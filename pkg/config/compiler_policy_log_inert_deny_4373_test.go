package config

import (
	"strings"
	"testing"
)

// buildPolicyLogInertTree parses flat set commands via the ParseSetCommand +
// SetPath loop (NewParser must not be used for set syntax — see CLAUDE.md
// "Testing flat set syntax").
func buildPolicyLogInertTree(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// policyLogInertBaseZones is the minimal zone/interface scaffolding the #4373
// per-policy cases reference (a trust->untrust zone pair).
var policyLogInertBaseZones = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security zones security-zone untrust interfaces ge-0/0/1.0",
}

// policyLogInertWarning returns the ValidateConfig warning that mentions the
// #4373 per-policy inert-log advisory, or "" if none was emitted.
func policyLogInertWarning(t *testing.T, cmds []string) string {
	t.Helper()
	cfg, err := CompileConfig(buildPolicyLogInertTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4373") && strings.Contains(w, "inert") {
			return w
		}
	}
	return ""
}

// TestPolicyLogInertOnDenyWarns is the #4373 (avo-review-007 E1) fail-on-revert
// guard: a NAMED or GLOBAL security policy with `then deny`/`then reject` plus
// `then log session-init`/`session-close` emits the commit-time inert-log
// advisory — the deny/reject verdict installs no session, so the requested
// RT_FLOW session-init/session-close record never fires. Reverting the
// validatePolicyLogInertOnDenyWarnings call (or the trigger) drops the warning
// and this test goes RED.
func TestPolicyLogInertOnDenyWarns(t *testing.T) {
	cases := []struct {
		name    string
		who     string   // fully-qualified policy substring the warning carries
		verdict string   // "deny" or "reject" the warning must name
		want    []string // additional substrings (configured modes)
		cmds    []string
	}{
		{
			name:    "zone-pair reject with session-close (E1 verbatim)",
			who:     "trust->untrust/p-reject",
			verdict: "reject",
			want:    []string{"session-close"},
			cmds: append(append([]string{}, policyLogInertBaseZones...),
				"set security policies from-zone trust to-zone untrust policy p-reject match source-address any",
				"set security policies from-zone trust to-zone untrust policy p-reject match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p-reject match application any",
				"set security policies from-zone trust to-zone untrust policy p-reject then reject",
				"set security policies from-zone trust to-zone untrust policy p-reject then log session-close",
			),
		},
		{
			name:    "zone-pair deny with session-init",
			who:     "trust->untrust/p-deny",
			verdict: "deny",
			want:    []string{"session-init"},
			cmds: append(append([]string{}, policyLogInertBaseZones...),
				"set security policies from-zone trust to-zone untrust policy p-deny match source-address any",
				"set security policies from-zone trust to-zone untrust policy p-deny match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p-deny match application any",
				"set security policies from-zone trust to-zone untrust policy p-deny then deny",
				"set security policies from-zone trust to-zone untrust policy p-deny then log session-init",
			),
		},
		{
			name:    "zone-pair deny with both modes",
			who:     "trust->untrust/p-both",
			verdict: "deny",
			want:    []string{"session-init", "session-close"},
			cmds: append(append([]string{}, policyLogInertBaseZones...),
				"set security policies from-zone trust to-zone untrust policy p-both match source-address any",
				"set security policies from-zone trust to-zone untrust policy p-both match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p-both match application any",
				"set security policies from-zone trust to-zone untrust policy p-both then deny",
				"set security policies from-zone trust to-zone untrust policy p-both then log session-init",
				"set security policies from-zone trust to-zone untrust policy p-both then log session-close",
			),
		},
		{
			name:    "global reject with session-close",
			who:     "global/g-reject",
			verdict: "reject",
			want:    []string{"session-close"},
			cmds: append(append([]string{}, policyLogInertBaseZones...),
				"set security policies global policy g-reject match source-address any",
				"set security policies global policy g-reject match destination-address any",
				"set security policies global policy g-reject match application any",
				"set security policies global policy g-reject then reject",
				"set security policies global policy g-reject then log session-close",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policyLogInertWarning(t, tc.cmds)
			if got == "" {
				t.Fatalf("expected a #4373 per-policy inert-log warning, got none")
			}
			if !strings.Contains(got, tc.who) {
				t.Errorf("warning %q missing policy id %q", got, tc.who)
			}
			if !strings.Contains(got, tc.verdict) {
				t.Errorf("warning %q missing verdict %q", got, tc.verdict)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("warning %q missing mode %q", got, w)
				}
			}
		})
	}
}

// TestPolicyLogPermitNoInertWarn confirms the warning is gated on the verdict:
// a `then permit` policy that configures `then log session-close` DOES install a
// session for the close record to fire on, so NO inert warning is emitted — the
// normal session-close logging path is unchanged.
func TestPolicyLogPermitNoInertWarn(t *testing.T) {
	cmds := append(append([]string{}, policyLogInertBaseZones...),
		"set security policies from-zone trust to-zone untrust policy p-permit match source-address any",
		"set security policies from-zone trust to-zone untrust policy p-permit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p-permit match application any",
		"set security policies from-zone trust to-zone untrust policy p-permit then permit",
		"set security policies from-zone trust to-zone untrust policy p-permit then log session-close",
	)
	if got := policyLogInertWarning(t, cmds); got != "" {
		t.Fatalf("unexpected inert-log warning under `then permit`: %q", got)
	}
}

// TestPolicyLogDenyNoLogNoWarn confirms the warning is gated on the log
// selection: a `then reject` policy with NO `then log` does not carry inert log
// flags, so no advisory fires (the advisory only surfaces a configured-but-inert
// selection, not every deny/reject).
func TestPolicyLogDenyNoLogNoWarn(t *testing.T) {
	cmds := append(append([]string{}, policyLogInertBaseZones...),
		"set security policies from-zone trust to-zone untrust policy p-silent match source-address any",
		"set security policies from-zone trust to-zone untrust policy p-silent match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p-silent match application any",
		"set security policies from-zone trust to-zone untrust policy p-silent then reject",
	)
	if got := policyLogInertWarning(t, cmds); got != "" {
		t.Fatalf("unexpected inert-log warning under a no-log `then reject`: %q", got)
	}
}
