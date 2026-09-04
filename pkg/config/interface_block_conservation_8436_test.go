package config

import "testing"

// #8436: the `interface` family — two blocks naming ONE interface merge, two
// blocks naming TWO interfaces still append.
//
// WHY THIS FAMILY WAS DEFERRED THREE TIMES, and why deferring it was wrong.
//
// Each previous batch stopped at these containers on the reasoning that they
// "may legitimately be append-both in Junos — an OSPF area with two `interface`
// blocks for DIFFERENT interfaces is normal authoring", so find-or-create might
// turn a correct append into a wrong merge.
//
// The premise is true and the conclusion does not follow. Find-or-create is
// keyed on the interface NAME: two blocks naming different interfaces do not
// match, so they still append. Only two blocks naming the SAME interface merge
// — which is the case the census builds (it uses one name for both blocks) and
// the only case that was ever wrong.
//
// That is an argument, so it is not left as one. The second cell below is the
// control, and it is the reason this family could finally be fixed: it fails if
// the merge is over-broad, which is exactly the risk that stopped three batches.

// The defect: two blocks, ONE interface name.
//
// `area.Interfaces` is a SLICE and the loop appended unconditionally, so this
// produced two entries with the same name. Whichever consumer reads first wins
// and the other block's settings are unreachable — the `system login class`
// shape, where a slice makes a lost block look like a merge.
func TestDuplicateOSPFInterfaceBlocksMerge8436(t *testing.T) {
	const cfgText = `
protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                cost 42;
            }
            interface ge-0/0/0.0 {
                priority 7;
            }
        }
    }
}
`
	cfg := mustCompile8436(t, cfgText)
	area := ospfArea8436(t, cfg, "0.0.0.0")
	if len(area.Interfaces) != 1 {
		t.Fatalf("one interface named twice produced %d entries, want 1. Two "+
			"entries with the same name means whichever consumer reads first "+
			"wins and the other block's settings never take effect (#8436)",
			len(area.Interfaces))
	}
	got := area.Interfaces[0]
	if got.Cost != 42 {
		t.Errorf("the FIRST block's cost was lost (Cost = %d, want 42)", got.Cost)
	}
	if !got.HasPriority || got.Priority != 7 {
		t.Errorf("the SECOND block's priority was lost (HasPriority=%v Priority=%d, want true/7)",
			got.HasPriority, got.Priority)
	}
}

// THE CONTROL, and the whole reason this family was safe to fix.
//
// Two blocks naming DIFFERENT interfaces must still produce TWO entries. A
// merge keyed on anything coarser than the name — or a fix that collapsed the
// container to a single entry — would break ordinary Junos authoring, and it
// would do so silently: one interface would simply stop being configured.
//
// Without this cell the fix above is indistinguishable from that mistake, which
// is precisely the concern that deferred this family three times.
func TestDistinctOSPFInterfaceBlocksStillAppend8436(t *testing.T) {
	const cfgText = `
protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                cost 42;
            }
            interface ge-0/0/1.0 {
                cost 43;
            }
        }
    }
}
`
	cfg := mustCompile8436(t, cfgText)
	area := ospfArea8436(t, cfg, "0.0.0.0")
	if len(area.Interfaces) != 2 {
		t.Fatalf("two DIFFERENT interfaces produced %d entries, want 2. The "+
			"find-or-create merge is over-broad: an area configuring two "+
			"interfaces would silently configure one (#8436)",
			len(area.Interfaces))
	}
	byName := map[string]int{}
	for _, i := range area.Interfaces {
		byName[i.Name] = i.Cost
	}
	if byName["ge-0/0/0.0"] != 42 || byName["ge-0/0/1.0"] != 43 {
		t.Errorf("the two interfaces did not keep their own settings: %v", byName)
	}
}

func mustCompile8436(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func ospfArea8436(t *testing.T, cfg *Config, name string) *OSPFArea {
	t.Helper()
	for _, a := range cfg.Protocols.OSPF.Areas {
		if a != nil && a.ID == name {
			return a
		}
	}
	t.Fatalf("area %s did not compile (areas: %d)", name, len(cfg.Protocols.OSPF.Areas))
	return nil
}
