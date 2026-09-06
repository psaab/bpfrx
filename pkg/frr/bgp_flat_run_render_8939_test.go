package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8939, the WIRE consequence, asserted where it is observable.
//
// "LocalAS stayed 0" and "FRR is handed no BGP configuration whatsoever" are
// not obviously the same statement, and the second is what sets the severity.
// `generateProtocols` gates the whole stanza on the AS:
//
//	if bgp != nil && bgp.LocalAS > 0 { "router bgp %d" … }
//
// so a dropped `local-as` does not degrade BGP, it DELETES it. Measured:
//
//	split           router bgp 65001 / bgp cluster-id 1.1.1.1 / bgp graceful-restart
//	packed          <nothing>
//
// The assertion is that both spellings render IDENTICALLY, which is stronger
// than grepping for `router bgp` and cannot be satisfied by a renderer that
// stops emitting BGP altogether.
func TestBGPFlatRunRendersIdenticallyForBothSpellings8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *config.Config {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, c := range cmds {
			p, err := config.ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg
	}
	m := &Manager{}
	bgpLines := func(cfg *config.Config) []string {
		out := m.generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)
		var got []string
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimSpace(l); strings.Contains(l, "bgp") {
				got = append(got, l)
			}
		}
		return got
	}

	b := "set protocols bgp "
	split := bgpLines(build(t, b+"graceful-restart", b+"cluster-id 1.1.1.1",
		b+"local-as 65001"))
	// REFERENCE ARM. Without it, a renderer that emitted nothing for BOTH arms
	// would make the comparison below pass against silence.
	if len(split) == 0 {
		t.Fatalf("the split arm rendered NO bgp lines; the comparison below would " +
			"pass against silence (#8939)")
	}

	packed := bgpLines(build(t, b+"graceful-restart cluster-id 1.1.1.1 local-as 65001"))
	if strings.Join(packed, "\n") != strings.Join(split, "\n") {
		t.Errorf("the packed spelling renders DIFFERENTLY:\n  packed: %v\n"+
			"  split:  %v\nA dropped `local-as` leaves LocalAS 0, and the whole "+
			"`router bgp` stanza is gated on it — FRR is handed no BGP "+
			"configuration at all while `show configuration` renders what the "+
			"operator typed (#8939)", packed, split)
	}
}
