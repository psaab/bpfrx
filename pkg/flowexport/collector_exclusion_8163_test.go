package flowexport

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8163 — a flow-server the config cannot express as a UDP destination used to
// be carried all the way to dialCollectors, which treats a dial failure as
// fatal for the WHOLE collector group. The failure then propagates out of
// NewExporter, and Daemon.reconcileFlowExporter's build loop `return`s on the
// FIRST constructor error, so one bad collector disabled export for EVERY
// group.
//
// Reachability is what sets the severity: nothing validates a flow-server port
// at commit (validateSamplingTemplateRefsStrict checks template references
// only), so `flow-server 10.0.0.2` with no `port` COMMITS CLEANLY. This is an
// operator typo silently disabling NetFlow, not a drift-only malformed state.
//
// The two cells below are deliberately separate. They fail for different
// reasons and a fix for one alone leaves the other live — see the comment on
// the cross-group cell.

// v9SvcWithTemplates builds a v9 service config defining the named templates.
func v9SvcWithTemplates8163(names ...string) *config.ServicesConfig {
	tmpls := map[string]*config.NetFlowV9Template{}
	for _, n := range names {
		tmpls[n] = &config.NetFlowV9Template{Name: n}
	}
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{Templates: tmpls},
		},
	}
}

func v9Server8163(addr string, port int, tmpl string) *config.FlowServer {
	return &config.FlowServer{
		Address:          addr,
		Port:             port,
		Version:          config.FlowServerVersion9,
		Version9Template: tmpl,
	}
}

// collectorAddrs8163 flattens the collector addresses of one group.
func collectorAddrs8163(ec *ExportConfig) []string {
	var out []string
	for _, c := range ec.Collectors {
		out = append(out, c.Address)
	}
	return out
}

// TestGoodCollectorStillExportsAlongsideABadOne8163 is acceptance cell 1 and
// the load-bearing one.
//
// One group, two collectors: one installable, one with no `port`. The good
// collector must still export.
//
// This is the cell that rejects the WRONG fix. Making
// Daemon.reconcileFlowExporter `continue` instead of `return` on a constructor
// error would satisfy the cross-group cell below while leaving this one red —
// the bad collector's own group, including its healthy sibling, would still be
// dropped. The exclusion has to happen where the collector list is BUILT, not
// where the failure is caught.
func TestGoodCollectorStillExportsAlongsideABadOne8163(t *testing.T) {
	svc := v9SvcWithTemplates8163("t1")
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"s1": {
					Name:      "s1",
					InputRate: 1,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							v9Server8163("10.0.0.1", 2055, "t1"), // installable
							v9Server8163("10.0.0.2", 0, "t1"),    // no `port`
						},
					},
				},
			},
		},
	}
	// Ground truth on BOTH servers, first. Without this a predicate that
	// stopped recognising the shape would make every assertion below agree on
	// "nothing to exclude" and the cell would pass over an empty set.
	good := fo.Sampling.Instances["s1"].FamilyInet.FlowServers[0]
	bad := fo.Sampling.Instances["s1"].FamilyInet.FlowServers[1]
	if r := config.FlowServerExcludedReason(good); r != "" {
		t.Fatalf("fixture's installable collector is excluded: %q", r)
	}
	if r := config.FlowServerExcludedReason(bad); r == "" {
		t.Fatal("fixture no longer constructs an excluded collector")
	}

	groups := ResolveV9TemplateGroups(svc, fo)
	if len(groups) != 1 {
		t.Fatalf("got %d export groups, want 1: %+v", len(groups), groups)
	}
	addrs := collectorAddrs8163(groups[0])
	if len(addrs) != 1 || addrs[0] != "10.0.0.1:2055" {
		t.Fatalf("group collectors = %v, want exactly [10.0.0.1:2055]. A "+
			"collector with no `port` reaches dialCollectors as the bare host "+
			"%q, which net.Dial rejects with `missing port in address` — and "+
			"that failure is fatal for the whole group.", addrs, "10.0.0.2")
	}

	// The end-to-end property the operator cares about: the exporter for this
	// group is CONSTRUCTIBLE. Asserting only the collector list would pass for
	// a fix that filtered the address but left something else undialable.
	exp, err := NewExporter(groups[0])
	if err != nil {
		t.Fatalf("NewExporter failed for a group containing a healthy "+
			"collector: %v\nOne unusable flow-server disables export for its "+
			"healthy siblings — and, via reconcileFlowExporter's build loop, "+
			"for every other group too.", err)
	}
	exp.Close()
}

// TestABadCollectorInOneGroupDoesNotKillAnother8163 is acceptance cell 2.
//
// Two template groups. Group `dead` holds ONLY an unusable collector; group
// `live` holds a healthy one. Group `live` must still export.
//
// Distinct from cell 1: that one is about a bad collector's SIBLINGS, this one
// is about the blast radius across groups, which is where
// reconcileFlowExporter's `return`-on-first-error turns a one-collector typo
// into a total export outage. A fix that only de-duplicated within a group
// would pass cell 1 and leave this live.
func TestABadCollectorInOneGroupDoesNotKillAnother8163(t *testing.T) {
	svc := v9SvcWithTemplates8163("dead", "live")
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"s1": {
					Name:      "s1",
					InputRate: 1,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							v9Server8163("10.0.0.2", 0, "dead"),    // only member, unusable
							v9Server8163("10.0.0.3", 2055, "live"), // healthy
						},
					},
				},
			},
		},
	}

	groups := ResolveV9TemplateGroups(svc, fo)

	// The `dead` group must not survive as an EMPTY group either. An empty
	// collector list dials successfully (the loop body never runs), so an
	// exporter would be published that can never send anything — a different
	// lie in the same family, and one this cell would otherwise wave through.
	byTemplate := map[string]*ExportConfig{}
	for _, g := range groups {
		byTemplate[g.TemplateName] = g
	}
	if g, ok := byTemplate["dead"]; ok {
		t.Errorf("a group was published for template %q whose only collector "+
			"is unusable (collectors=%v); it can never send a record",
			"dead", collectorAddrs8163(g))
	}

	live, ok := byTemplate["live"]
	if !ok {
		t.Fatalf("template group \"live\" is absent; an unusable collector in "+
			"ANOTHER group removed it. Got groups: %v", func() []string {
			var n []string
			for _, g := range groups {
				n = append(n, g.TemplateName)
			}
			return n
		}())
	}
	if addrs := collectorAddrs8163(live); len(addrs) != 1 || addrs[0] != "10.0.0.3:2055" {
		t.Fatalf("live group collectors = %v, want [10.0.0.3:2055]", addrs)
	}

	// Every group the resolver publishes must be constructible. This is the
	// closest faithful model of Daemon.reconcileFlowExporter's build loop,
	// which calls NewExporter on each in turn and returns on the first error —
	// so one group that cannot be built takes every other group with it.
	for _, g := range groups {
		exp, err := NewExporter(g)
		if err != nil {
			t.Fatalf("NewExporter failed for template group %q: %v\n"+
				"reconcileFlowExporter returns on the FIRST constructor error, "+
				"so this disables export for every group, not just this one.",
				g.TemplateName, err)
		}
		exp.Close()
	}
}

// TestEveryExcludedPortShapeIsDropped8163 pins the boundary per REASON rather
// than testing only the port-0 shape the issue was filed about.
//
// Port 0 and an out-of-range port reach dialCollectors by DIFFERENT routes —
// the bare host for 0 (`missing port in address`), a joined `host:70000` for
// the out-of-range case (`invalid port`) — so a fix that only special-cased
// `Port == 0` would leave the second live.
func TestEveryExcludedPortShapeIsDropped8163(t *testing.T) {
	for _, tc := range []struct {
		name string
		port int
	}{
		{"absent_port_sentinel", 0},
		{"negative_port", -1},
		{"above_u16", 65536},
		{"far_above_u16", 70000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := v9SvcWithTemplates8163("t1")
			fo := &config.ForwardingOptionsConfig{
				Sampling: &config.SamplingConfig{
					Instances: map[string]*config.SamplingInstance{
						"s1": {Name: "s1", InputRate: 1, FamilyInet: &config.SamplingFamily{
							FlowServers: []*config.FlowServer{
								v9Server8163("10.0.0.1", 2055, "t1"),
								v9Server8163("10.0.0.9", tc.port, "t1"),
							},
						}},
					},
				},
			}
			bad := fo.Sampling.Instances["s1"].FamilyInet.FlowServers[1]
			if r := config.FlowServerExcludedReason(bad); r == "" {
				t.Fatalf("fixture port %d is not excluded by the shared "+
					"predicate; this case tests nothing", tc.port)
			}
			groups := ResolveV9TemplateGroups(svc, fo)
			if len(groups) != 1 {
				t.Fatalf("got %d groups, want 1", len(groups))
			}
			for _, a := range collectorAddrs8163(groups[0]) {
				if strings.Contains(a, "10.0.0.9") {
					t.Fatalf("unusable collector %q survived into the group", a)
				}
			}
			exp, err := NewExporter(groups[0])
			if err != nil {
				t.Fatalf("NewExporter failed: %v", err)
			}
			exp.Close()
		})
	}
}
