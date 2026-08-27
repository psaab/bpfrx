package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6893 — THE PAYLOAD PROOF for the VLAN-sub-interface fail-open.
//
// The filed harm: a VLAN sub-interface that fails to be created is soft-skipped
// by compileZones, compileFirewallFilters then resolves the same name, misses,
// and `continue`s — so the operator commits a config containing a filter
// binding, the commit reports SUCCESS, and the filter is not applied. A filter
// that is absent permits what it was configured to deny.
//
// This cell demonstrates that outcome rather than assuming it, which is what
// makes the record it also asserts worth having: an absence claim is only as
// good as the payload's ability to produce what it asserts is absent.
//
// The seam is `ifCache`. Seeding the PHYSICAL interface and leaving the VLAN
// child absent reproduces exactly the post-soft-skip state — the parent
// resolves, `ge-0-0-2.50` does not — with no netlink and no privileges.
//
// WHAT THIS CELL WILL BECOME. #6893's fix direction 1 makes a VLAN creation
// failure fail the apply. When that lands, the `err != nil` assertion here
// inverts, and that inversion is its done-signal. Until then this pins the
// CURRENT behaviour honestly, including that it is a fail-open.
func TestVLANSubInterfaceFilterSilentlyUnapplied_6893(t *testing.T) {
	const physName = "ge-0-0-2"
	const subName = "ge-0-0-2.50"

	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"wan-in": {
			Name:  "wan-in",
			Terms: []*config.FirewallFilterTerm{{Name: "deny-all", Action: "discard"}},
		},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		physName: {
			Name: physName,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, FilterInputV4: "wan-in"},
			},
		},
	}

	dp := newIfaceFilterRecordingDP6893()
	// The parent resolves; the VLAN child does not — the state compileZones
	// leaves behind when ensureVLANSubInterface failed and it soft-skipped.
	result := &CompileResult{
		ifCache: map[string]*net.Interface{
			physName: {Index: 42, Name: physName},
		},
	}

	err := compileFirewallFilters(dp, cfg, result)

	// THE FAIL-OPEN, demonstrated. The compile succeeds even though the filter
	// the operator bound could not be assigned to anything.
	if err != nil {
		t.Fatalf("compileFirewallFilters returned %v — this cell pins the CURRENT "+
			"fail-open, in which the compile SUCCEEDS. If #6893 fix direction 1 has "+
			"landed, invert this assertion rather than deleting it: a failing apply "+
			"is the intended end state", err)
	}

	// Guard the fixture: if the filter had actually been assigned, everything
	// below would be asserting against a case that never arose.
	if len(dp.ifaceFilters) != 0 {
		t.Fatalf("fixture broken: the filter WAS assigned (%d bindings) — the VLAN "+
			"child must be unresolvable for this cell to mean anything", len(dp.ifaceFilters))
	}

	// THE RECORD (#6893 part 1). The cause was already recorded by
	// compiler_iface.go's soft skip; before this change the CONSEQUENCE — the
	// binding that never reached the dataplane — left no structured trace.
	bindings := result.UnappliedFilterBindings()
	if len(bindings) != 1 {
		t.Fatalf("want exactly 1 unapplied-binding record, got %d (%+v) — without it "+
			"a filter that silently went missing is undetectable except by reading logs",
			len(bindings), bindings)
	}
	b := bindings[0]
	if b.Interface != subName {
		t.Errorf("record names interface %q, want %q — the record must name the "+
			"CONFIGURED surface, or a VLAN child folds onto its parent", b.Interface, subName)
	}
	if len(b.Filters) != 1 || !strings.Contains(b.Filters[0], "wan-in") {
		t.Errorf("record filters = %v, want one naming wan-in — a record that does not "+
			"say WHICH binding was dropped cannot tell an operator what is unenforced",
			b.Filters)
	}
	if !strings.Contains(b.Reason, "VLAN sub-interface") {
		t.Errorf("record reason = %q, want the VLAN resolution failure — the physical-miss "+
			"and VLAN-miss paths must stay distinguishable", b.Reason)
	}
}

// The CONTROL. With the VLAN child resolvable the filter IS assigned and
// nothing is recorded — so the assertions above cannot pass against a build
// that never assigns filters at all, or one that records unconditionally.
func TestVLANSubInterfaceFilterAppliedWhenResolvable_6893(t *testing.T) {
	const physName = "ge-0-0-2"
	const subName = "ge-0-0-2.50"

	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"wan-in": {
			Name:  "wan-in",
			Terms: []*config.FirewallFilterTerm{{Name: "deny-all", Action: "discard"}},
		},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		physName: {
			Name:  physName,
			Units: map[int]*config.InterfaceUnit{50: {Number: 50, VlanID: 50, FilterInputV4: "wan-in"}},
		},
	}

	dp := newIfaceFilterRecordingDP6893()
	result := &CompileResult{
		ifCache: map[string]*net.Interface{
			physName: {Index: 42, Name: physName},
			subName:  {Index: 43, Name: subName},
		},
	}

	if err := compileFirewallFilters(dp, cfg, result); err != nil {
		t.Fatalf("compileFirewallFilters: %v", err)
	}
	if len(dp.ifaceFilters) == 0 {
		t.Error("the filter must be ASSIGNED when the VLAN child resolves — without this " +
			"control the fail-open cell above proves nothing about the VLAN miss")
	}
	if got := result.UnappliedFilterBindings(); len(got) != 0 {
		t.Errorf("nothing may be recorded when the binding APPLIED, got %+v", got)
	}
}

// ifaceFilterRecordingDP6893 extends the package's recordingFilterDP with the
// interface->filter assignment, which is the thing these cells are about: the
// fail-open is precisely that SetIfaceFilter is never reached.
type ifaceFilterRecordingDP6893 struct {
	*recordingFilterDP
	ifaceFilters map[IfaceFilterKey]uint32
}

func newIfaceFilterRecordingDP6893() *ifaceFilterRecordingDP6893 {
	return &ifaceFilterRecordingDP6893{
		recordingFilterDP: &recordingFilterDP{},
		ifaceFilters:      map[IfaceFilterKey]uint32{},
	}
}

func (d *ifaceFilterRecordingDP6893) SetIfaceFilter(key IfaceFilterKey, id uint32) error {
	d.ifaceFilters[key] = id
	return nil
}
