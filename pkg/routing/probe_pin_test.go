package routing

import (
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeProbePinOps is an in-memory probePinOps double. The fail* hooks
// inject per-call failures keyed by rule priority / route table so the
// #1895 per-pin install-result tests can break exactly one pin.
type fakeProbePinOps struct {
	rules        []netlink.Rule
	routes       []netlink.Route
	links        map[string]int // name → ifindex
	failRuleAdd  map[int]error  // rule priority → error
	failRouteAdd map[int]error  // route table → error
	ruleDelCalls int
}

func (f *fakeProbePinOps) RuleAdd(r *netlink.Rule) error {
	if err, ok := f.failRuleAdd[r.Priority]; ok {
		return err
	}
	f.rules = append(f.rules, *r)
	return nil
}

func (f *fakeProbePinOps) RuleDel(r *netlink.Rule) error {
	f.ruleDelCalls++
	for i := range f.rules {
		if f.rules[i].Priority == r.Priority && f.rules[i].Family == r.Family {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("rule not found: prio %d", r.Priority)
}

func (f *fakeProbePinOps) RuleList(family int) ([]netlink.Rule, error) {
	var out []netlink.Rule
	for _, r := range f.rules {
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeProbePinOps) RouteAdd(r *netlink.Route) error {
	if err, ok := f.failRouteAdd[r.Table]; ok {
		return err
	}
	f.routes = append(f.routes, *r)
	return nil
}

func (f *fakeProbePinOps) RouteDel(r *netlink.Route) error {
	for i := range f.routes {
		if f.routes[i].Table == r.Table && f.routes[i].Dst.String() == r.Dst.String() {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("route not found: table %d", r.Table)
}

func (f *fakeProbePinOps) RouteListFiltered(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
	var out []netlink.Route
	for _, r := range f.routes {
		if r.Table != filter.Table {
			continue
		}
		isV6 := r.Dst != nil && r.Dst.IP.To4() == nil
		if (family == unix.AF_INET6) != isV6 {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeProbePinOps) LinkByName(name string) (netlink.Link, error) {
	idx, ok := f.links[name]
	if !ok {
		return nil, fmt.Errorf("link %q not found", name)
	}
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
}

func rpmConfigWithPins() *config.RPMConfig {
	return &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			// Same target via two uplinks — the normal dual-WAN pattern
			// (#1827 §4.2.4 named test).
			"via-a": {Name: "via-a", Target: "1.1.1.1", NextHop: "172.16.50.1", DestinationInterface: "reth0.50"},
			"via-b": {Name: "via-b", Target: "1.1.1.1", NextHop: "172.16.80.1", DestinationInterface: "reth0.80"},
			"plain": {Name: "plain", Target: "8.8.8.8"},
		}},
		"AUX": {Name: "AUX", Tests: map[string]*config.RPMTest{
			"v6": {Name: "v6", Target: "2001:db8::1", NextHop: "fe80::1", DestinationInterface: "ge-0/0/3.0"},
		}},
	}}
}

func TestBuildProbePinsDeterministicAssignment(t *testing.T) {
	rethMap := map[string]string{"reth0": "ge-0/0/2"}
	pins := BuildProbePins(rpmConfigWithPins(), rethMap)
	if len(pins) != 3 {
		t.Fatalf("len(pins) = %d, want 3 (only next-hop tests pinned)", len(pins))
	}
	// Sorted probe then test order: AUX/v6, WAN/via-a, WAN/via-b.
	wantKeys := []string{"AUX/v6", "WAN/via-a", "WAN/via-b"}
	for i, pin := range pins {
		if pin.TestKey != wantKeys[i] {
			t.Fatalf("pins[%d].TestKey = %q, want %q", i, pin.TestKey, wantKeys[i])
		}
		if pin.Index != i {
			t.Fatalf("pins[%d].Index = %d, want %d", i, pin.Index, i)
		}
		if got, want := pin.Mark, uint32(config.ProbeFwmarkBase+i); got != want {
			t.Fatalf("pins[%d].Mark = %#x, want %#x", i, got, want)
		}
		if got, want := pin.Table, config.ProbeTableBase+i; got != want {
			t.Fatalf("pins[%d].Table = %d, want %d", i, got, want)
		}
		if got, want := pin.Priority, config.ProbeRulePriorityBase+i; got != want {
			t.Fatalf("pins[%d].Priority = %d, want %d", i, got, want)
		}
	}

	// Same target via two uplinks gets DISTINCT tables and marks.
	if pins[1].Target != pins[2].Target {
		t.Fatalf("test setup: targets differ")
	}
	if pins[1].Table == pins[2].Table || pins[1].Mark == pins[2].Mark {
		t.Fatalf("same-target pins must use distinct tables/marks: %+v vs %+v", pins[1], pins[2])
	}

	// Interface resolution: RETH VLAN unit + plain Junos unit name.
	if got, want := pins[1].Interface, "ge-0-0-2.50"; got != want {
		t.Fatalf("pins[1].Interface = %q, want %q", got, want)
	}
	if got, want := pins[0].Interface, "ge-0-0-3"; got != want {
		t.Fatalf("pins[0].Interface = %q, want %q", got, want)
	}

	// Determinism: a second build yields the same assignment.
	again := BuildProbePins(rpmConfigWithPins(), rethMap)
	for i := range pins {
		if pins[i] != again[i] {
			t.Fatalf("assignment not deterministic at %d: %+v vs %+v", i, pins[i], again[i])
		}
	}
}

func TestBuildProbePinsCap(t *testing.T) {
	cfg := &config.RPMConfig{Probes: map[string]*config.RPMProbe{}}
	probe := &config.RPMProbe{Name: "big", Tests: map[string]*config.RPMTest{}}
	for i := 0; i < config.ProbeTableCount+5; i++ {
		name := fmt.Sprintf("t%03d", i)
		probe.Tests[name] = &config.RPMTest{
			Name: name, Target: "1.1.1.1", NextHop: "10.0.0.1", DestinationInterface: "ge-0/0/0",
		}
	}
	cfg.Probes["big"] = probe
	pins := BuildProbePins(cfg, nil)
	if len(pins) != config.ProbeTableCount {
		t.Fatalf("len(pins) = %d, want capped at %d", len(pins), config.ProbeTableCount)
	}
}

func TestProbePinApplyProgramsRulesAndRoutes(t *testing.T) {
	ops := &fakeProbePinOps{links: map[string]int{
		"ge-0-0-2.50": 11, "ge-0-0-2.80": 12, "ge-0-0-3": 13,
	}}
	p := &probePinManager{ops: ops}
	rethMap := map[string]string{"reth0": "ge-0/0/2"}
	pins := BuildProbePins(rpmConfigWithPins(), rethMap)

	if failed := p.Apply(pins); len(failed) != 0 {
		t.Fatalf("Apply reported failures: %v", failed)
	}
	if len(ops.rules) != 3 {
		t.Fatalf("len(rules) = %d, want 3", len(ops.rules))
	}
	if len(ops.routes) != 3 {
		t.Fatalf("len(routes) = %d, want 3", len(ops.routes))
	}
	for i, pin := range pins {
		r := ops.rules[i]
		if r.Mark != pin.Mark || r.Table != pin.Table || r.Priority != pin.Priority {
			t.Fatalf("rule[%d] = %+v, want mark/table/prio from %+v", i, r, pin)
		}
		rt := ops.routes[i]
		if rt.Table != pin.Table {
			t.Fatalf("route[%d].Table = %d, want %d", i, rt.Table, pin.Table)
		}
		if rt.Flags&int(netlink.FLAG_ONLINK) == 0 {
			t.Fatalf("route[%d] missing onlink flag", i)
		}
		if !rt.Gw.Equal(net.ParseIP(pin.NextHop)) {
			t.Fatalf("route[%d].Gw = %v, want %v", i, rt.Gw, pin.NextHop)
		}
		ones, bits := rt.Dst.Mask.Size()
		if ones != bits {
			t.Fatalf("route[%d] not a host route: /%d of %d", i, ones, bits)
		}
	}
}

func TestProbePinClearRemovesOnlyBand(t *testing.T) {
	// Band/table cleanup on restart (#1827 §4.2.4 named test): stale
	// pins from a crashed daemon are flushed; unrelated rules/routes in
	// other bands are untouched.
	_, stale1, _ := net.ParseCIDR("1.1.1.1/32")
	_, stale2, _ := net.ParseCIDR("2001:db8::1/128")
	_, other, _ := net.ParseCIDR("10.0.0.0/8")
	ops := &fakeProbePinOps{
		links: map[string]int{},
		rules: []netlink.Rule{
			{Priority: config.ProbeRulePriorityBase, Family: unix.AF_INET, Table: config.ProbeTableBase},
			{Priority: config.ProbeRulePriorityBase + 7, Family: unix.AF_INET6, Table: config.ProbeTableBase + 7},
			{Priority: 100, Family: unix.AF_INET, Table: 101},   // next-table band
			{Priority: 31000, Family: unix.AF_INET, Table: 102}, // PBR band
		},
		routes: []netlink.Route{
			{Table: config.ProbeTableBase, Dst: stale1},
			{Table: config.ProbeTableBase + 7, Dst: stale2},
			{Table: 254, Dst: other},
		},
	}
	p := &probePinManager{ops: ops}
	if err := p.clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(ops.rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2 (out-of-band preserved): %+v", len(ops.rules), ops.rules)
	}
	for _, r := range ops.rules {
		if r.Priority >= config.ProbeRulePriorityBase && r.Priority < config.ProbeRulePriorityBase+config.ProbeTableCount {
			t.Fatalf("band rule survived clear: %+v", r)
		}
	}
	if len(ops.routes) != 1 || ops.routes[0].Table != 254 {
		t.Fatalf("probe-table routes not flushed (or main-table route lost): %+v", ops.routes)
	}
}

func TestResolveProbeInterface(t *testing.T) {
	rethMap := map[string]string{"reth0": "ge-0/0/2"}
	cases := []struct{ in, want string }{
		{"", ""},
		{"reth0.50", "ge-0-0-2.50"},
		{"reth0.0", "ge-0-0-2"},
		{"reth0", "ge-0-0-2"},
		{"ge-0/0/3.0", "ge-0-0-3"},
		{"ge-0/0/3.80", "ge-0-0-3.80"},
		{"fxp0", "fxp0"},
	}
	for _, c := range cases {
		if got := ResolveProbeInterface(c.in, rethMap); got != c.want {
			t.Fatalf("ResolveProbeInterface(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- #1895: per-pin install results + rollback ---

// twoPinConfig returns a config with exactly two pinned tests sharing
// one probe: index 0 = WAN/a (prio 50, table 7000), index 1 = WAN/b
// (prio 51, table 7001).
func twoPinConfig() *config.RPMConfig {
	return &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"a": {Name: "a", Target: "1.1.1.1", NextHop: "10.0.0.1", DestinationInterface: "ge-0/0/1"},
			"b": {Name: "b", Target: "9.9.9.9", NextHop: "10.0.1.1", DestinationInterface: "ge-0/0/2"},
		}},
	}}
}

func TestProbePinApplyRuleAddFailureReported(t *testing.T) {
	ops := &fakeProbePinOps{
		links:       map[string]int{"ge-0-0-1": 11, "ge-0-0-2": 12},
		failRuleAdd: map[int]error{config.ProbeRulePriorityBase: fmt.Errorf("EBUSY")},
	}
	p := &probePinManager{ops: ops}
	pins := BuildProbePins(twoPinConfig(), nil)

	failed := p.Apply(pins)
	if len(failed) != 1 {
		t.Fatalf("failed = %v, want exactly WAN/a", failed)
	}
	if err, ok := failed["WAN/a"]; !ok || err == nil {
		t.Fatalf("WAN/a missing from failed map: %v", failed)
	}
	// The failed pin must leave nothing installed; the healthy pin must
	// be fully installed.
	if len(ops.rules) != 1 || ops.rules[0].Priority != config.ProbeRulePriorityBase+1 {
		t.Fatalf("rules = %+v, want only WAN/b's rule", ops.rules)
	}
	if len(ops.routes) != 1 || ops.routes[0].Table != config.ProbeTableBase+1 {
		t.Fatalf("routes = %+v, want only WAN/b's route", ops.routes)
	}
}

func TestProbePinApplyRouteAddFailureRollsBackRule(t *testing.T) {
	ops := &fakeProbePinOps{
		links:        map[string]int{"ge-0-0-1": 11, "ge-0-0-2": 12},
		failRouteAdd: map[int]error{config.ProbeTableBase + 1: fmt.Errorf("ENETUNREACH")},
	}
	p := &probePinManager{ops: ops}
	pins := BuildProbePins(twoPinConfig(), nil)

	failed := p.Apply(pins)
	if len(failed) != 1 {
		t.Fatalf("failed = %v, want exactly WAN/b", failed)
	}
	if err, ok := failed["WAN/b"]; !ok || err == nil {
		t.Fatalf("WAN/b missing from failed map: %v", failed)
	}
	// Partial install must not persist: WAN/b's fwmark rule was added
	// before RouteAdd failed and must be rolled back, leaving only
	// WAN/a's rule+route.
	if len(ops.rules) != 1 || ops.rules[0].Priority != config.ProbeRulePriorityBase {
		t.Fatalf("rules = %+v, want only WAN/a's rule (WAN/b rolled back)", ops.rules)
	}
	if ops.ruleDelCalls == 0 {
		t.Fatal("RuleDel was never called for the rollback")
	}
	if len(ops.routes) != 1 || ops.routes[0].Table != config.ProbeTableBase {
		t.Fatalf("routes = %+v, want only WAN/a's route", ops.routes)
	}
}

func TestProbePinApplyMissingLinkReported(t *testing.T) {
	// Only WAN/a's egress link exists (boot ordering / RETH churn).
	ops := &fakeProbePinOps{links: map[string]int{"ge-0-0-1": 11}}
	p := &probePinManager{ops: ops}
	pins := BuildProbePins(twoPinConfig(), nil)

	failed := p.Apply(pins)
	if len(failed) != 1 {
		t.Fatalf("failed = %v, want exactly WAN/b", failed)
	}
	if _, ok := failed["WAN/b"]; !ok {
		t.Fatalf("WAN/b missing from failed map: %v", failed)
	}
	if len(ops.rules) != 1 || len(ops.routes) != 1 {
		t.Fatalf("healthy pin not fully installed: rules=%+v routes=%+v", ops.rules, ops.routes)
	}
}

func TestProbePinApplyInvalidAddressReported(t *testing.T) {
	cfg := &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"bad": {Name: "bad", Target: "not-an-ip", NextHop: "10.0.0.1", DestinationInterface: "ge-0/0/1"},
		}},
	}}
	ops := &fakeProbePinOps{links: map[string]int{"ge-0-0-1": 11}}
	p := &probePinManager{ops: ops}

	failed := p.Apply(BuildProbePins(cfg, nil))
	if len(failed) != 1 {
		t.Fatalf("failed = %v, want exactly WAN/bad", failed)
	}
	if _, ok := failed["WAN/bad"]; !ok {
		t.Fatalf("WAN/bad missing from failed map: %v", failed)
	}
	if len(ops.rules) != 0 || len(ops.routes) != 0 {
		t.Fatalf("nothing should be installed: rules=%+v routes=%+v", ops.rules, ops.routes)
	}
}

func TestProbePinApplyRecoveryClearsFailure(t *testing.T) {
	// First apply fails (missing link); after the link appears, a
	// re-apply returns no failures and fully installs the pin.
	ops := &fakeProbePinOps{links: map[string]int{"ge-0-0-1": 11}}
	p := &probePinManager{ops: ops}
	pins := BuildProbePins(twoPinConfig(), nil)

	if failed := p.Apply(pins); len(failed) != 1 {
		t.Fatalf("first apply: failed = %v, want 1", failed)
	}
	ops.links["ge-0-0-2"] = 12
	if failed := p.Apply(pins); len(failed) != 0 {
		t.Fatalf("re-apply after link appeared: failed = %v, want none", failed)
	}
	if len(ops.rules) != 2 || len(ops.routes) != 2 {
		t.Fatalf("both pins must be installed: rules=%+v routes=%+v", ops.rules, ops.routes)
	}
}
