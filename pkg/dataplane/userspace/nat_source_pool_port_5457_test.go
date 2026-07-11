// #5457: a source-NAT pool with an invalid `port [range]` (rejected by
// parseSourcePoolPortRange) must not install the defaulted 1024-65535 range on
// the tolerant load / peer-sync path. The compiler leaves PortLow/PortHigh at
// the default and records PortRangeInvalidSpec; the snapshot builder
// (sourceNATPoolPortRange) reads that marker and marks the pool UNUSABLE, so a
// leniently-loaded bad range installs nothing rather than PAT-translating over a
// range the operator never configured.
//
// RED-on-revert (snapshot builder marker check removed): the pool falls back to
// the defaulted 1024-65535 range and PoolUnusable comes back false.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileSNATPoolLenient(t *testing.T, poolCmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := append([]string{}, poolCmds...)
	cmds = append(cmds,
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool p1",
	)
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// The strict path hard-rejects these ranges (validateSourceNATPoolStrict);
	// exercise the tolerant path so a snapshot is actually built.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func TestSourceNATSnapshotInvalidPortRangeUnusable_5457(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"reversed", "set security nat source pool p1 port range low 5000 high 100"},
		{"neg-low-over-high", "set security nat source pool p1 port range low -1 high 99999"},
		{"zero-low", "set security nat source pool p1 port range low 0 high 5000"},
		{"over-single", "set security nat source pool p1 port 99999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSNATPoolLenient(t,
				"set security nat source pool p1 address 203.0.113.5/32",
				tc.cmd)
			snaps := buildSourceNATSnapshots(cfg, nil)
			if len(snaps) != 1 {
				t.Fatalf("snapshots = %d, want 1", len(snaps))
			}
			s := snaps[0]
			if !s.PoolUnusable {
				t.Fatalf("%q: PoolUnusable = false, want true (invalid range must fail closed, not default to 1024-65535)", tc.name)
			}
			if s.PoolUnusableReason != "invalid_port_range" {
				t.Fatalf("%q: PoolUnusableReason = %q, want invalid_port_range", tc.name, s.PoolUnusableReason)
			}
		})
	}
}
