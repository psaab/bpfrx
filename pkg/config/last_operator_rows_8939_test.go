package config

import (
	"reflect"
	"testing"
)

func build8939h(t *testing.T, lines ...string) *Config {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	c, err := CompileConfig(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// #8939 at `system archival configuration`: a packed run set only the first
// option, so an archive uploaded on commit but never on a schedule (or the
// reverse) — and a backup that silently stops happening is discovered when it
// is needed.
func TestArchivalConfigurationPackedRun8939(t *testing.T) {
	split := build8939h(t,
		"set system archival configuration transfer-on-commit",
		"set system archival configuration transfer-interval 30")
	if a := split.System.Archival; a == nil || !a.TransferOnCommit || a.TransferInterval == 0 {
		t.Fatalf("the SPLIT control did not set both: %+v", a)
	}
	packed := build8939h(t, "set system archival configuration transfer-on-commit transfer-interval 30")
	if !reflect.DeepEqual(packed, split) {
		t.Errorf("packed %+v\nsplit  %+v", packed.System.Archival, split.System.Archival)
	}
	only := build8939h(t, "set system archival configuration transfer-on-commit")
	if a := only.System.Archival; !a.TransferOnCommit || a.TransferInterval != 0 {
		t.Errorf("`transfer-on-commit` alone gave onCommit=%v interval=%d, want true/0",
			a.TransferOnCommit, a.TransferInterval)
	}
}

// #8939 at `services rpm probe <p> test <t>`: a packed run lost every property
// AFTER the target, because SetPath nests them UNDER it.
//
//	set … test T target address 10.0.0.1 probe-type icmp-ping probe-count 5
//	  [test T] > [target] > [address 10.0.0.1] > [probe-type …] > [probe-count …]
//	  -> target=10.0.0.1  probe-type=""  probe-count=0
//
// A probe running with the wrong TYPE is a probe that does not detect what it
// was configured to detect — and `services ip-monitoring` drives preferred-route
// injection off these results.
//
// THIS ROW IS INVISIBLE TO THE #8939 CENSUS, which is why it needs its own cell.
// The census builds a fixture from two ELIGIBLE leaves (childless, non-multi),
// and `target` owns a body — so the fixture it generates for this container
// cannot produce the nesting that loses the properties. The row the census DOES
// carry here, `target [address | url]`, is a different thing: those two are
// ALTERNATIVES that both write `test.Target`, so a fixture setting both is
// malformed input rather than a loss. That row is a census artifact and is
// recorded as such rather than "fixed".
func TestRPMProbeTestPackedRun8939(t *testing.T) {
	split := build8939h(t,
		"set services rpm probe P test T target address 10.0.0.1",
		"set services rpm probe P test T probe-type icmp-ping",
		"set services rpm probe P test T probe-count 5")
	find := func(c *Config) *RPMTest {
		if c.Services.RPM == nil {
			return nil
		}
		for _, p := range c.Services.RPM.Probes {
			for _, tt := range p.Tests {
				return tt
			}
		}
		return nil
	}
	s := find(split)
	if s == nil || s.Target == "" || s.ProbeType == "" || s.ProbeCount == 0 {
		t.Fatalf("the SPLIT control did not set all three: %+v", s)
	}

	packed := build8939h(t,
		"set services rpm probe P test T target address 10.0.0.1 probe-type icmp-ping probe-count 5")
	if !reflect.DeepEqual(packed, split) {
		p := find(packed)
		t.Errorf("packed target=%q type=%q count=%d, split target=%q type=%q count=%d",
			p.Target, p.ProbeType, p.ProbeCount, s.Target, s.ProbeType, s.ProbeCount)
	}

	// BOTH target spellings must still resolve. The hoist lifts statements out
	// of `target`'s body; lifting `address`/`url` themselves would empty it.
	for _, tc := range []struct{ line, want string }{
		{"set services rpm probe P test T target address 10.0.0.1", "10.0.0.1"},
		{"set services rpm probe P test T target url http://x/", "http://x/"},
	} {
		got := find(build8939h(t, tc.line))
		if got == nil || got.Target != tc.want {
			t.Errorf("%q gave target=%v, want %q", tc.line, got, tc.want)
		}
	}

	// NARROWNESS: a target alone must not invent a probe type or count.
	only := find(build8939h(t, "set services rpm probe P test T target address 10.0.0.1"))
	if only.ProbeType != "" || only.ProbeCount != 0 {
		t.Errorf("a bare target also set type=%q count=%d", only.ProbeType, only.ProbeCount)
	}
}
