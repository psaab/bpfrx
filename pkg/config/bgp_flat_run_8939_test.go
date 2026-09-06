package config

import "testing"

// #8939 on `protocols bgp`, and the consequence is not a lost setting — it is
// THE WHOLE PROTOCOL.
//
//	set protocols bgp graceful-restart cluster-id 1.1.1.1 local-as 65001
//	  -> GracefulRestart=true  ClusterID=""  LocalAS=0
//
// pkg/frr gates the ENTIRE stanza on the AS number:
//
//	if bgp != nil && bgp.LocalAS > 0 { fmt.Fprintf(&b, "router bgp %d…") … }
//
// so with LocalAS 0 FRR receives **no `router bgp` block at all** — no
// sessions, no routes, no BGP — while `show configuration` renders exactly
// what the operator typed. A dropped leaf that happens to be a GUARD for
// everything downstream of it does not degrade the feature, it deletes it.
// The wire half is asserted in pkg/frr/bgp_flat_run_render_8939_test.go.
//
// OPERATOR-REACHABLE, AND ONLY IN THE FLAG-FIRST ORDERING:
//
//	cluster-id 1.1.1.1 graceful-restart local-as 65001   SCHEMA-REJECT
//	local-as 65001 cluster-id 1.1.1.1 graceful-restart   SCHEMA-REJECT
//	graceful-restart cluster-id 1.1.1.1 local-as 65001   ACCEPTED
//
// `graceful-restart` is args:0 and untyped and `protocols bgp` is open-world —
// the #9148 conjunction — and starting a line with the bare flag is an
// ordinary way to type it. This is the second container (after
// router-advertisement, #9180) where the ONLY admitted ordering is the natural
// one, which is why the census's union over first-leaf positions is the
// instrument that matters and a single-ordering probe is not.
func TestBGPFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *BGPConfig {
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

	b := "set protocols bgp "
	// Flag first: the ordering that is ADMITTED at commit.
	ref := build(t, b+"graceful-restart", b+"cluster-id 1.1.1.1", b+"local-as 65001")
	if !ref.GracefulRestart || ref.ClusterID == "" || ref.LocalAS == 0 {
		t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
			"below would pass against a BGP config that carries nothing (#8939)", ref)
	}

	for _, tc := range []struct{ name, cmd string }{
		{"two leaves", b + "graceful-restart cluster-id 1.1.1.1"},
		// THE WIDTH A RECURSIVE DESCENT FAILS (#9079) -- and here the third
		// leaf is the one the whole stanza is gated on.
		{"three leaves", b + "graceful-restart cluster-id 1.1.1.1 local-as 65001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, tc.cmd)
			if got.ClusterID != ref.ClusterID {
				t.Errorf("cluster-id = %q, want %q -- a route reflector with no "+
					"cluster-id falls back to its router-id, so two RRs in one "+
					"redundant cluster stop recognising each other's reflected "+
					"routes (#8939)", got.ClusterID, ref.ClusterID)
			}
			if tc.name == "three leaves" && got.LocalAS != ref.LocalAS {
				t.Errorf("local-as = %d, want %d -- pkg/frr renders NO `router bgp` "+
					"stanza at all when this is 0, so the operator's entire BGP "+
					"configuration silently reaches FRR as nothing (#8939)",
					got.LocalAS, ref.LocalAS)
			}
		})
	}
}
