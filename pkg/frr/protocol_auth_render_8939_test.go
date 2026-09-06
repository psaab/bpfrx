package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8939, the WIRE consequence, asserted where it is observable.
//
// The compiler-side cell (pkg/config/protocol_auth_flat_run_8939_test.go)
// asserts the dropped leaf. This one asserts what the drop DID, because
// "authentication-type is empty" and "the key goes out in cleartext" are not
// obviously the same statement, and the second is the reason this row
// outranked every other OPERATOR row on the board:
//
//	split   area-password md5 secret1     / ip rip authentication mode md5
//	packed  area-password clear secret1   / ip rip authentication mode text
//
// The assertion is that the two spellings render IDENTICALLY, which is
// stronger than checking for `md5` and cannot be satisfied by a renderer that
// stops emitting authentication altogether.
func TestProtocolAuthRendersIdenticallyForBothSpellings8939(t *testing.T) {
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
	render := func(cfg *config.Config) string {
		return m.generateProtocols(nil, nil, nil, cfg.Protocols.RIP, cfg.Protocols.ISIS,
			"", 0, nil, nil)
	}
	authLines := func(s string) []string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if strings.Contains(l, "password") || strings.Contains(l, "authentication") {
				out = append(out, l)
			}
		}
		return out
	}

	for _, tc := range []struct{ name, base, extra string }{
		{"isis", "set protocols isis ", "net 49.0001.0000.0000.0001.00"},
		{"rip", "set protocols rip ", "neighbor ge-0/0/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.base
			split := authLines(render(build(t, b+tc.extra,
				b+"authentication-key secret1", b+"authentication-type md5")))
			// REFERENCE ARM. Without this a renderer that emits nothing at all
			// would make the comparison below trivially pass.
			if len(split) == 0 {
				t.Fatalf("the split arm rendered NO authentication lines; the " +
					"comparison below would pass against silence (#8939)")
			}
			var sawMD5 bool
			for _, l := range split {
				if strings.Contains(l, "md5") {
					sawMD5 = true
				}
			}
			if !sawMD5 {
				t.Fatalf("the split arm rendered no md5 line (%v); the premise of "+
					"this cell is that the WORKING spelling produces md5 (#8939)", split)
			}

			packed := authLines(render(build(t, b+tc.extra,
				b+"authentication-key secret1 authentication-type md5")))
			if strings.Join(packed, "\n") != strings.Join(split, "\n") {
				t.Errorf("the packed spelling renders DIFFERENTLY:\n  packed: %v\n"+
					"  split:  %v\nA dropped authentication-type downgrades the "+
					"adjacency to plaintext and puts the key on the wire, with no "+
					"warning -- AuthTypeUnrecognized(\"\") is false so #8443 stays "+
					"silent (#8939)", packed, split)
			}
		})
	}
}
