// #5818: NPTv6 (RFC 6296) rule-sets accept the full static-NAT match scope in
// the config model — rule-set `from interface` / `from routing-instance` and
// per-rule `match source-address` — but the NPTv6 snapshot/wire/dataplane carry
// ONLY `from zone` (Nptv6RuleSnapshot has no interface/routing-instance/source
// field). Emitting a scope-carrying rule installs an over-broad zone/global
// rewrite that translates traffic the operator scoped OUT (security-widening).
//
// The strict commit gate (validateNPTv6ScopeStrict) rejects such a rule; on the
// tolerant load / peer-sync path that gate only warns (#1960 no-brick), so the
// snapshot builder must independently FAIL CLOSED — EXCLUDING the scope-carrying
// rule so nothing installs rather than a widened rewrite.
//
// RED-on-revert (snapshot builder scope check removed): the scoped rule ships as
// a from-zone snapshot (len == 1) and silently widens the rewrite.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileNptv6ScopeLenient builds a config from flat-set commands via the
// tolerant path (the strict path hard-rejects a scoped NPTv6 rule, #5818), so a
// snapshot is actually produced and the builder's fail-closed exclusion can be
// asserted.
func compileNptv6ScopeLenient(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	base := []string{"set security zones security-zone trust"}
	for _, cmd := range append(base, cmds...) {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestNptv6SnapshotScopeFailClosed_5818: an NPTv6 rule carrying an unsupported
// scope dimension (from-interface, from-routing-instance, or match source-
// address) is EXCLUDED from the snapshot — the builder installs nothing rather
// than a widened from-zone/global rewrite. RED-on-revert: the builder emits the
// rule and len(snaps) == 1.
func TestNptv6SnapshotScopeFailClosed_5818(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"from-interface", []string{
			"set security nat static rule-set rs1 from interface ge-0/0/1.0",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48"}},
		{"from-routing-instance", []string{
			"set security nat static rule-set rs1 from routing-instance blue",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48"}},
		{"match-source-address", []string{
			"set security nat static rule-set rs1 from zone trust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 match source-address 2001:db8:100::/64",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileNptv6ScopeLenient(t, tc.cmds...)
			snaps := buildNptv6Snapshots(cfg)
			if len(snaps) != 0 {
				t.Fatalf("buildNptv6Snapshots = %d snapshots, want 0 (scope-carrying NPTv6 rule must fail closed, not ship a widened rewrite): %+v", len(snaps), snaps)
			}
		})
	}
}

// TestNptv6SnapshotFromZoneOnlyStillInstalls_5818 is the control: a from-zone-
// only NPTv6 rule (the #5176-correct path) still produces exactly one snapshot
// carrying the zone and both prefixes — the fail-closed exclusion must not touch
// the supported path.
func TestNptv6SnapshotFromZoneOnlyStillInstalls_5818(t *testing.T) {
	cfg := compileNptv6ScopeLenient(t,
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48")
	snaps := buildNptv6Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("buildNptv6Snapshots = %d snapshots, want 1 (from-zone-only NPTv6 rule is supported)", len(snaps))
	}
	s := snaps[0]
	if s.FromZone != "trust" {
		t.Fatalf("FromZone = %q, want trust", s.FromZone)
	}
	if s.ExternalPrefix != "2001:db8:1::/48" || s.InternalPrefix != "fd00:1::/48" {
		t.Fatalf("prefixes = (ext %q, int %q), want (2001:db8:1::/48, fd00:1::/48)", s.ExternalPrefix, s.InternalPrefix)
	}
}
