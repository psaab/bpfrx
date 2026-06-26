package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSnapshotDefaultPolicyFailsClosed is the dataplane-side #3065
// fail-on-revert guard. The Rust no-match verdict is driven entirely by the
// ConfigSnapshot.DefaultPolicy string (policy.rs parse_action ->
// PolicyState.default_action). A config compiled WITHOUT a
// `security policies default-policy` stanza must serialize as "deny", so the
// userspace dataplane denies unmatched zone-pair traffic. If the
// compiler's DefaultPolicy=PolicyDeny initializer is reverted, the zero
// value (PolicyPermit) ships "permit" and this test goes RED.
func TestSnapshotDefaultPolicyFailsClosed(t *testing.T) {
	compile := func(t *testing.T, cmds []string) *config.Config {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}

	base := []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
	}

	cases := []struct {
		name  string
		extra []string
		want  string
	}{
		{"implicit-no-stanza", nil, "deny"},
		{"explicit-permit-all", []string{"set security policies default-policy permit-all"}, "permit"},
		{"explicit-deny-all", []string{"set security policies default-policy deny-all"}, "deny"},
		{"explicit-reject-all", []string{"set security policies default-policy reject-all"}, "reject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compile(t, append(append([]string{}, base...), tc.extra...))
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1, RingEntries: 2048}, 1, 1)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if snap.DefaultPolicy != tc.want {
				t.Fatalf("snap.DefaultPolicy = %q, want %q", snap.DefaultPolicy, tc.want)
			}
		})
	}
}
