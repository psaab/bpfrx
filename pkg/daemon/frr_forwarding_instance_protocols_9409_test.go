package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
)

// #9409, the runtime half. The strict gate rejects this composition at commit,
// so anything that reaches the assembler arrived on a TOLERANT path — boot from
// an already-persisted config, or HA config-sync — where #1960 forbids refusing
// to start. That downgrade is only safe if the assembler makes the stanza
// INERT: an empty VRFName means "the GLOBAL instance" to generateProtocols, so
// carrying the protocols through is what put an instance-scoped IGP in the
// global routing context and an instance-scoped BGP neighbor in the GLOBAL AS.

func lenientCfg9409(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not reject (#1960): %v", err)
	}
	return cfg
}

const fwdProtoCfg9409 = `
interfaces {
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
routing-options { autonomous-system 65001; }
protocols {
    ospf { area 0.0.0.0 { interface ge-0/0/1.0; } }
    bgp { group g { type external; peer-as 65001; neighbor 10.0.0.1; } }
}
routing-instances { ISP-B { instance-type forwarding;
    routing-options { static { route 0.0.0.0/0 next-hop 10.0.1.254; } }
    protocols {
        ospf { area 0.0.0.0 { interface ge-0/0/1.0; } }
        bgp { group h { type external; peer-as 65002; neighbor 10.0.0.2; } }
        rip { group r { neighbor ge-0/0/1.0; } }
        isis { interface ge-0/0/1.0; }
    } } }
`

func TestAssemblerDropsForwardingInstanceProtocols9409(t *testing.T) {
	cfg := lenientCfg9409(t, fwdProtoCfg9409)
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)

	if len(fc.Instances) != 1 {
		t.Fatalf("Instances = %+v, want one", fc.Instances)
	}
	inst := fc.Instances[0]
	if inst.VRFName != "" || inst.TableID == 0 {
		t.Fatalf("the forwarding instance must keep VRFName=\"\" + a table id "+
			"(#1827 PR-2): %+v", inst)
	}
	for _, p := range []struct {
		name string
		nil_ bool
	}{
		{"OSPF", inst.OSPF == nil},
		{"OSPFv3", inst.OSPFv3 == nil},
		{"BGP", inst.BGP == nil},
		{"RIP", inst.RIP == nil},
		{"ISIS", inst.ISIS == nil},
	} {
		if !p.nil_ {
			t.Errorf("the forwarding instance still carries %s. VRFName is \"\" for "+
				"this instance, and generateProtocols reads that as the GLOBAL "+
				"instance — so this renders the instance's protocol in the global "+
				"routing context (#9409).", p.name)
		}
	}

	// The statics are the whole point of the instance and must survive.
	if len(inst.StaticRoutes) != 1 {
		t.Fatalf("the forwarding instance's statics were dropped: %+v", inst)
	}

	// #9141 class: the drop must not reach back into the active config, or
	// `show configuration` stops matching what was committed.
	if cfg.RoutingInstances[0].OSPF == nil {
		t.Error("assembleFRRConfig mutated the active config's routing instance")
	}
}

// TestGlobalProtocolsRenderExactlyOnce9409 is the acceptance criterion stated in
// the issue, asserted on the RENDERED managed section rather than on the
// assembled struct. Before this change the same fixture produced TWO
// `router ospf` blocks (neither carrying a `vrf` suffix) and the instance's
// `peer-as 65002` neighbor under a SECOND `router bgp 65001` — a silent merge
// into the global AS.
func TestGlobalProtocolsRenderExactlyOnce9409(t *testing.T) {
	cfg := lenientCfg9409(t, fwdProtoCfg9409)
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)

	dir := t.TempDir()
	conf := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(conf, []byte("frr version 10.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := frr.NewForTest(conf, &frr.RecordingExecutor{})
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	for _, tc := range []struct {
		stanza string
		want   int
	}{
		{"router ospf\n", 1},
		{"router bgp 65001\n", 1},
		{"router rip\n", 0},
		{"router isis", 0},
	} {
		if n := strings.Count(got, tc.stanza); n != tc.want {
			t.Errorf("%q rendered %d times, want %d:\n%s", tc.stanza, n, tc.want, got)
		}
	}
	// The decisive one: the instance's neighbor must not appear at all. Under
	// the defect it rendered inside the global `router bgp 65001`, which is a
	// peering the operator never asked the global AS to make.
	if strings.Contains(got, "10.0.0.2") {
		t.Errorf("the forwarding instance's BGP neighbor reached the managed section; "+
			"it renders under the GLOBAL `router bgp 65001`, joining the global AS:\n%s", got)
	}
	// Positive control in the same render: the GLOBAL protocols are still there,
	// so the counts above are not passing because everything vanished.
	if !strings.Contains(got, "neighbor 10.0.0.1 remote-as 65001") {
		t.Errorf("the global BGP neighbor is missing — this cell measured a config "+
			"that rendered nothing:\n%s", got)
	}
	if !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
		t.Errorf("the global OSPF activation is missing:\n%s", got)
	}
	// And the instance's statics still render into its own kernel table.
	if !strings.Contains(got, "table ") {
		t.Errorf("the forwarding instance's statics no longer render into `table <id>` "+
			"(#1827 PR-2):\n%s", got)
	}
}
