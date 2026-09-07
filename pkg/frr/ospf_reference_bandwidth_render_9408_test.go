package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9408 END-TO-END: operator token -> compiled Mbps -> rendered FRR line.
//
// The three layers were each pinned in isolation and NONE of the pins crossed
// the unit boundary, which is how a bits/s leaf could feed an Mbps directive
// unconverted for as long as it did:
//
//   - pkg/config's parser cell authored `10g` and asserted only `ospf != nil`;
//   - pkg/frr's render cell asserted "int in, int out" and said nothing about
//     units;
//   - nothing at all drove a token through the compiler INTO the renderer.
//
// This cell is that missing edge. Reverting the compiler to `strconv.Atoi`
// reds it in both directions at once: `1g` renders nothing, and `1000000000`
// renders `auto-cost reference-bandwidth 1000000000`, which is 233 times
// FRR's documented maximum.
func TestOSPFReferenceBandwidthCompilesAndRenders9408(t *testing.T) {
	compile := func(t *testing.T, token string) *config.OSPFConfig {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range []string{
			"set protocols ospf reference-bandwidth " + token,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
		} {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%v): %v", path, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", token, err)
		}
		return cfg.Protocols.OSPF
	}

	m := New()
	for _, tc := range []struct {
		token string
		want  string
	}{
		{"1g", " auto-cost reference-bandwidth 1000\n"},
		{"1000000000", " auto-cost reference-bandwidth 1000\n"},
		{"100m", " auto-cost reference-bandwidth 100\n"},
		{"10g", " auto-cost reference-bandwidth 10000\n"},
	} {
		got := m.generateProtocols(compile(t, tc.token), nil, nil, nil, nil, "", 1, nil, nil)
		if !strings.Contains(got, tc.want) {
			t.Errorf("reference-bandwidth %s: missing %q in:\n%s", tc.token, tc.want, got)
		}
		// The rendered number is the operator's bits/s value divided by 10^6.
		// Assert the RAW token never appears on the auto-cost line, or an
		// unconverted passthrough would satisfy the substring check above for
		// any token that happens to equal its own Mbps value.
		for _, line := range strings.Split(got, "\n") {
			if strings.Contains(line, "auto-cost reference-bandwidth") &&
				strings.HasSuffix(strings.TrimSpace(line), " "+tc.token) {
				t.Errorf("reference-bandwidth %s: the raw operator token was rendered VERBATIM into an "+
					"Mbps directive: %q", tc.token, line)
			}
		}
	}

	// A value the gate rejects compiles to UNSET on the tolerant path, and the
	// renderer must then emit NO auto-cost line — not a zero, and not the raw
	// token. This is the half that keeps a stale persisted config from putting
	// an out-of-grammar line into the managed section.
	got := m.generateProtocols(compile(t, "10000"), nil, nil, nil, nil, "", 1, nil, nil)
	if strings.Contains(got, "auto-cost reference-bandwidth") {
		t.Errorf("an unconvertible reference-bandwidth must render NO auto-cost line; got:\n%s", got)
	}
	// CONTROL that the fixture is not simply producing an empty stanza.
	if !strings.Contains(got, "router ospf") {
		t.Errorf("CONTROL: the OSPF stanza itself must still render; got:\n%s", got)
	}
}
