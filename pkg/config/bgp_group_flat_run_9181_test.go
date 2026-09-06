package config

import "testing"

// #9181: `protocols bgp group` drops the tail of a packed run, and when the
// tail is a CONTAINER the loss is total and silent.
//
//	set protocols bgp group G peer-as 65001 neighbor 10.0.0.1
//	  -> neighbors=0, no error
//
// `neighbor` nests under `peer-as`, so the two-pass group walk never sees a
// child named `neighbor` and pass 1 stamps nothing. **The group is configured
// with nobody in it** — which reads as intentional in a way a missing value
// does not.
//
// THREE SPELLINGS ARE ASSERTED, NOT ONE, and that is not thoroughness for its
// own sake: it found a second broken spelling. team-lead's #9017 lesson is
// that declaring or reading a leaf verified on ONE spelling is necessary and
// not sufficient — they shipped a schema declaration that worked on the
// flat-set and compact-body paths and left `family any filter F { … }` still
// minting zero filters. Measured here BEFORE the fix:
//
//	flat SPLIT      neighbors=1     hier NESTED     neighbors=1
//	flat PACKED     neighbors=0     hier ONE-LINE   neighbors=0
//
// The one-line braced spelling fails identically and was not in the report.
// Both are the same nested-chain AST, so one fix covers both — but only a cell
// that ASKS about both can say so.
//
// CHANNEL, MEASURED ON BOTH GRAMMARS, because the severity differs by
// ordering and the reported example is not the operator-reachable one:
//
//	flat  peer-as 65001 neighbor 10.0.0.1                 SCHEMA-REJECT
//	flat  default-originate description "d" peer-as 65001 ACCEPTED
//	hier  group G { peer-as 65001 neighbor 10.0.0.1; }    rejected, unknown modifier
//	hier  group G { default-originate description … ; }   rejected, #8437 fused statement
//
// So the container-tail case is `lenient-only` — it reaches the compiler via
// Store.Load and Store.SyncApply, not the keyboard — while the FLAG-FIRST
// ordering is operator-typed, because `default-originate` is args:0 and
// untyped and the container is open-world (#9148's conjunction).
func TestBGPGroupFlatRunKeepsEveryLeaf9181(t *testing.T) {
	flat := func(t *testing.T, cmds ...string) *BGPConfig {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil || cfg.Protocols.BGP == nil {
			t.Fatalf("compile produced no BGP config: %v", err)
		}
		return cfg.Protocols.BGP
	}
	hier := func(t *testing.T, text string) *BGPConfig {
		t.Helper()
		cfg, err := CompileConfigLenient(hierTree(t, text))
		if err != nil || cfg == nil || cfg.Protocols.BGP == nil {
			t.Fatalf("compile produced no BGP config: %v", err)
		}
		return cfg.Protocols.BGP
	}
	only := func(t *testing.T, g *BGPConfig) *BGPNeighbor {
		t.Helper()
		if len(g.Neighbors) != 1 {
			t.Fatalf("want exactly 1 neighbor, got %d -- a group configured with "+
				"nobody in it (#9181)", len(g.Neighbors))
		}
		return g.Neighbors[0]
	}

	pre := "set protocols bgp local-as 65000"
	b := "set protocols bgp group G "

	// REFERENCE ARM: the spelling that always worked. If this stops carrying a
	// neighbor, every comparison below passes against an empty group.
	ref := only(t, flat(t, pre, b+"peer-as 65001", b+"neighbor 10.0.0.1"))
	if ref.Address == "" || ref.PeerAS == 0 {
		t.Fatalf("the split reference arm is incomplete (%+v) (#9181)", ref)
	}

	t.Run("flat packed, container tail", func(t *testing.T) {
		got := only(t, flat(t, pre, b+"peer-as 65001 neighbor 10.0.0.1"))
		if got.Address != ref.Address || got.PeerAS != ref.PeerAS {
			t.Errorf("neighbor = %s/AS%d, want %s/AS%d (#9181)",
				got.Address, got.PeerAS, ref.Address, ref.PeerAS)
		}
	})

	// THE SPELLING THAT WAS NOT IN THE REPORT. Same nested-chain AST, so the
	// same fix covers it -- asserted rather than assumed.
	t.Run("hierarchical one-line braced", func(t *testing.T) {
		got := only(t, hier(t, `protocols {
    bgp {
        local-as 65000;
        group G { peer-as 65001 neighbor 10.0.0.1; }
    }
}`))
		if got.Address != ref.Address || got.PeerAS != ref.PeerAS {
			t.Errorf("one-line braced neighbor = %s/AS%d, want %s/AS%d -- the "+
				"spelling a flat-set-only probe never asks about (#9181)",
				got.Address, got.PeerAS, ref.Address, ref.PeerAS)
		}
	})

	// The MULTI-STATEMENT braced spelling must be unaffected: it already
	// worked, and a segmentation bug would break it.
	t.Run("hierarchical nested must still work", func(t *testing.T) {
		got := only(t, hier(t, `protocols {
    bgp {
        local-as 65000;
        group G {
            peer-as 65001;
            neighbor 10.0.0.1;
        }
    }
}`))
		if got.Address != ref.Address || got.PeerAS != ref.PeerAS {
			t.Errorf("nested braced neighbor = %s/AS%d, want %s/AS%d (#9181)",
				got.Address, got.PeerAS, ref.Address, ref.PeerAS)
		}
	})

	// THE OPERATOR-REACHABLE ORDERING, and the width a recursive descent
	// fails: three leaves after the flag.
	t.Run("flag-first, three leaves", func(t *testing.T) {
		refN := only(t, flat(t, pre, b+"neighbor 10.0.0.1", b+"default-originate",
			b+`description "d1"`, b+"peer-as 65001"))
		if !refN.DefaultOriginate || refN.Description == "" || refN.PeerAS == 0 {
			t.Fatalf("the split reference arm is incomplete (%+v) (#9181)", refN)
		}
		got := only(t, flat(t, pre, b+"neighbor 10.0.0.1",
			b+`default-originate description "d1" peer-as 65001`))
		if got.DefaultOriginate != refN.DefaultOriginate ||
			got.Description != refN.Description || got.PeerAS != refN.PeerAS {
			t.Errorf("flag-first packed = {defOrig:%v desc:%q peerAS:%d}, want "+
				"{%v %q %d} -- this is the ordering that COMMITS, so it is the "+
				"operator-reachable one (#9181)",
				got.DefaultOriginate, got.Description, got.PeerAS,
				refN.DefaultOriginate, refN.Description, refN.PeerAS)
		}
	})
}
