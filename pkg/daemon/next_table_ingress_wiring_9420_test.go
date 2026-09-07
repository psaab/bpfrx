package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// recordingRuleOps9420 records every rule the applier installs so a test can
// inspect the SELECTORS, not just the count.
type recordingRuleOps9420 struct {
	added []netlink.Rule
}

func (f *recordingRuleOps9420) RuleAdd(r *netlink.Rule) error {
	f.added = append(f.added, *r)
	return nil
}
func (f *recordingRuleOps9420) RuleDel(*netlink.Rule) error          { return nil }
func (f *recordingRuleOps9420) RuleList(int) ([]netlink.Rule, error) { return nil, nil }
func (f *recordingRuleOps9420) RuleAddDSCP(r *netlink.Rule, _ uint8) error {
	f.added = append(f.added, *r)
	return nil
}

// TestApplyRoutingRulesWiresNextTableIngressScope_9420 binds the CALL SITE, not
// the function.
//
// pkg/routing's own cells prove nextTableManager.Apply scopes what it is given.
// They say nothing about whether the daemon actually derives and passes the
// scoping set: replacing routing.DefaultInstanceIngressIfaces(cfg) in
// applyRoutingRules with any hard-coded slice leaves every pkg/routing cell
// green while the shipped daemon scopes leaks to an interface that has nothing
// to do with the config. This drives the REAL applyRoutingRules against a config
// whose default instance owns ge-0/0/0 and whose VRF owns ge-0/0/1, and asserts
// the emitted rules are scoped to the DEFAULT instance's interface and to
// NOTHING else.
//
// FAIL-ON-REVERT: pass nil, or any constant, for ingressIfaces in
// applyRoutingRules and this goes red.
func TestApplyRoutingRulesWiresNextTableIngressScope_9420(t *testing.T) {
	fake := &recordingRuleOps9420{}
	d := &Daemon{routing: routing.NewManagerWithRuleOpsForTest(fake)}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, Interfaces: []string{"ge-0/0/1"}},
	}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
	}

	if err := d.applyRoutingRules(cfg, nil); err != nil {
		t.Fatalf("applyRoutingRules: %v", err)
	}

	var leaks []netlink.Rule
	for _, r := range fake.added {
		if r.Table == 101 {
			leaks = append(leaks, r)
		}
	}
	if len(leaks) == 0 {
		t.Fatal("POSITIVE CONTROL: no next-table leak rule was installed at all — " +
			"the scope assertions below would be vacuously satisfied")
	}
	for _, r := range leaks {
		if r.IifName == "" {
			t.Errorf("leak rule %v carries no ingress scope (#9420)", r)
		}
		// The VRF's own interface must never be a scoping interface for a leak
		// authored in the default instance — that is the cross-VRF steer.
		if r.IifName == "ge-0-0-1" {
			t.Errorf("leak rule %v is scoped to the VRF's OWN interface; the daemon "+
				"is not deriving the scoping set from the config (#9420)", r)
		}
		if r.IifName != "ge-0-0-0" {
			t.Errorf("leak rule %v scoped to %q, want the default instance's "+
				"ge-0-0-0", r, r.IifName)
		}
	}
}
