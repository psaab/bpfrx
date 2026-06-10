package config

import (
	"strings"
	"testing"
)

// rpmProbeLines returns the set lines for a probe the ip-monitoring
// policies under test can reference.
func rpmProbeLines() []string {
	return []string{
		"set services rpm probe WAN test wan-a probe-type icmp-ping",
		"set services rpm probe WAN test wan-a target address 1.1.1.1",
		"set services rpm probe WAN test wan-a destination-interface reth0.50",
		"set services rpm probe WAN test wan-a next-hop 172.16.50.1",
		"set services rpm probe WAN test wan-a thresholds successive-loss 3",
	}
}

// TestIPMonitoringFlatSet covers the plan §4.1 example config in flat
// set syntax (ParseSetCommand + SetPath).
func TestIPMonitoringFlatSet(t *testing.T) {
	lines := append(rpmProbeLines(),
		"set routing-instances ISP-B instance-type virtual-router",
		"set services ip-monitoring policy wan-failover match rpm-probe WAN",
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 172.16.80.1",
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 preferred-metric 10",
		"set services ip-monitoring policy wan-failover then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.80.1",
		"set services ip-monitoring policy wan-failover hold-down 5",
	)
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pol := cfg.Services.IPMonitoring.Policies["wan-failover"]
	if pol == nil {
		t.Fatal("policy wan-failover not compiled")
	}
	if pol.MatchRPMProbe != "WAN" {
		t.Fatalf("MatchRPMProbe = %q, want WAN", pol.MatchRPMProbe)
	}
	if pol.HoldDownSecs != 5 {
		t.Fatalf("HoldDownSecs = %d, want 5", pol.HoldDownSecs)
	}
	if len(pol.PreferredRoutes) != 2 {
		t.Fatalf("PreferredRoutes = %+v, want 2 (master merged + ISP-B)", pol.PreferredRoutes)
	}
	master := pol.PreferredRoutes[0]
	if master.RoutingInstance != "" || master.Destination != "0.0.0.0/0" ||
		master.NextHop != "172.16.80.1" || master.PreferredMetric != 10 {
		t.Fatalf("master route = %+v (next-hop and preferred-metric lines must merge)", master)
	}
	ri := pol.PreferredRoutes[1]
	if ri.RoutingInstance != "ISP-B" || ri.NextHop != "172.16.80.1" {
		t.Fatalf("routing-instance route = %+v", ri)
	}
}

// TestIPMonitoringHierarchical covers the same stanza in hierarchical
// block syntax.
func TestIPMonitoringHierarchical(t *testing.T) {
	input := `services {
    rpm {
        probe WAN {
            test wan-a {
                target address 1.1.1.1;
                destination-interface reth0.50;
                next-hop 172.16.50.1;
            }
        }
    }
    ip-monitoring {
        policy wan-failover {
            match {
                rpm-probe WAN;
            }
            then {
                preferred-route {
                    route 0.0.0.0/0 {
                        next-hop 172.16.80.1;
                        preferred-metric 10;
                    }
                    routing-instance ISP-B {
                        route 0.0.0.0/0 {
                            next-hop 172.16.80.1;
                        }
                    }
                }
            }
            hold-down 5;
        }
    }
}
routing-instances {
    ISP-B {
        instance-type virtual-router;
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pol := cfg.Services.IPMonitoring.Policies["wan-failover"]
	if pol == nil || pol.MatchRPMProbe != "WAN" || pol.HoldDownSecs != 5 {
		t.Fatalf("policy = %+v", pol)
	}
	if len(pol.PreferredRoutes) != 2 {
		t.Fatalf("PreferredRoutes = %+v, want 2", pol.PreferredRoutes)
	}
	if pol.PreferredRoutes[0].PreferredMetric != 10 {
		t.Fatalf("master metric = %d, want 10", pol.PreferredRoutes[0].PreferredMetric)
	}
	if pol.PreferredRoutes[1].RoutingInstance != "ISP-B" {
		t.Fatalf("second route = %+v", pol.PreferredRoutes[1])
	}
}

func TestIPMonitoringValidation(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{
			name: "unknown probe rejected",
			lines: []string{
				"set services ip-monitoring policy p match rpm-probe NOPE",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
			},
			wantErr: "does not reference a configured services rpm probe",
		},
		{
			name: "missing match rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
			),
			wantErr: "match rpm-probe is required",
		},
		{
			name: "missing preferred-route rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
			),
			wantErr: "at least one then preferred-route route is required",
		},
		{
			name: "family mismatch rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 2001:db8::1",
			),
			wantErr: "address family does not match destination",
		},
		{
			name: "invalid destination rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route not-a-prefix next-hop 10.0.0.1",
			),
			wantErr: "invalid destination prefix",
		},
		{
			name: "unknown routing-instance rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route routing-instance GHOST route 0.0.0.0/0 next-hop 10.0.0.1",
			),
			wantErr: `routing-instance "GHOST" does not exist`,
		},
		{
			name: "forwarding instance-type rejected",
			lines: append(rpmProbeLines(),
				"set routing-instances FBF instance-type forwarding",
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route routing-instance FBF route 0.0.0.0/0 next-hop 10.0.0.1",
			),
			wantErr: "instance-type forwarding, which is not supported yet",
		},
		{
			name: "negative hold-down rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
				"set services ip-monitoring policy p hold-down -3",
			),
			wantErr: "hold-down: invalid value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
