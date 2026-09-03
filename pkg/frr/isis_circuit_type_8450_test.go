package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderISISIfaces8450(t *testing.T, ifs ...*config.ISISInterface) string {
	t.Helper()
	m := &Manager{}
	got := m.generateProtocols(nil, nil, nil, nil,
		&config.ISISConfig{NET: "49.0001.1921.6800.1001.00", Level: "level-1-2", Interfaces: ifs},
		"", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") {
		t.Fatalf("render did not reach the IS-IS block at all")
	}
	return got
}

// #8450a: ISISInterface.Level was compiled, stored, and NEVER rendered — no
// `isis circuit-type` line existed anywhere in pkg/frr, so an interface an
// operator restricted to one level kept forming adjacencies at the router-wide
// is-type. Dead config that fails OPEN.
func TestISISInterfaceCircuitTypeIsRendered_8450(t *testing.T) {
	cases := map[string]string{
		"1":            "isis circuit-type level-1",
		"2":            "isis circuit-type level-2-only",
		"1-2":          "isis circuit-type level-1-2",
		"level-1":      "isis circuit-type level-1",
		"level-2":      "isis circuit-type level-2-only",
		"level-2-only": "isis circuit-type level-2-only",
		"level-1-2":    "isis circuit-type level-1-2",
	}
	for authored, want := range cases {
		got := renderISISIfaces8450(t, &config.ISISInterface{Name: "ge-0/0/1", Level: authored})
		if !strings.Contains(got, want) {
			t.Errorf("interface level %q rendered no %q — the interface stays at the "+
				"router-wide is-type:\n%s", authored, want, got)
		}
	}
}

// An UNSET level must render NO circuit-type line: that is how an interface
// inherits the router-wide is-type in both FRR and Junos. A fix that emitted a
// default here would narrow every interface in every existing config.
func TestISISInterfaceUnsetLevelRendersNoCircuitType_8450(t *testing.T) {
	got := renderISISIfaces8450(t, &config.ISISInterface{Name: "ge-0/0/1", Metric: 10})
	if strings.Contains(got, "circuit-type") {
		t.Errorf("an interface with no authored level rendered a circuit-type line — "+
			"every existing config would be silently narrowed:\n%s", got)
	}
	// CONTROL: the interface block IS being rendered, so the absence above is
	// an absence of the line and not of the block.
	if !strings.Contains(got, "isis metric 10") {
		t.Errorf("the interface block was not rendered at all; the assertion above is vacuous:\n%s", got)
	}
}

// #8450b: only `ip router isis` was emitted, so isisd ran IPv4-only and IS-IS
// carried no IPv6 routes at all.
func TestISISInterfaceEnablesIPv6Topology_8450(t *testing.T) {
	got := renderISISIfaces8450(t, &config.ISISInterface{Name: "ge-0/0/1"})
	for _, want := range []string{" ip router isis xpf", " ipv6 router isis xpf"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q — IS-IS does not carry that address family:\n%s", want, got)
		}
	}
}

// An unrecognised value must render NO line rather than a broken one: one
// rejected line fails the WHOLE managed-section reload (#1880/#2223), which is
// far worse than an interface inheriting the router-wide level.
func TestISISInterfaceUnknownLevelRendersNoLine_8450(t *testing.T) {
	for _, bad := range []string{"garbage", "level-3", "LEVEL-1", "3"} {
		got := renderISISIfaces8450(t, &config.ISISInterface{Name: "ge-0/0/1", Level: bad})
		if strings.Contains(got, "circuit-type") {
			t.Errorf("interface level %q rendered a circuit-type line; an invalid argument "+
				"fails the entire frr-reload:\n%s", bad, got)
		}
	}
}

// The circuit-type must land INSIDE the interface block, before `exit`.
// `isis circuit-type` is interface-scoped; emitted at global scope vtysh
// rejects it and one rejected line fails the whole reload — the exact ordering
// hazard #2942 recorded for per-interface BFD.
func TestISISCircuitTypeIsInsideTheInterfaceBlock_8450(t *testing.T) {
	got := renderISISIfaces8450(t, &config.ISISInterface{Name: "ge-0/0/1", Level: "level-1"})
	inBlock, sawIt := false, false
	for _, ln := range strings.Split(got, "\n") {
		if strings.HasPrefix(ln, "interface ge-0/0/1") {
			inBlock = true
			continue
		}
		if inBlock && ln == "exit" {
			inBlock = false
			continue
		}
		if strings.Contains(ln, "circuit-type") {
			sawIt = true
			if !inBlock {
				t.Errorf("`%s` was emitted OUTSIDE the interface block — vtysh rejects it "+
					"at global scope and one rejected line fails the whole reload", strings.TrimSpace(ln))
			}
		}
	}
	if !sawIt {
		t.Fatal("no circuit-type line at all; this cell asserted nothing")
	}
}
